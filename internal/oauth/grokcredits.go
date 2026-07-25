package oauth

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"time"
)

// grokCreditsEndpoint is the gRPC-Web unary call behind grok.com's Settings →
// Usage panel ("Weekly SuperGrok Heavy Limit — NN% used"). It is the only
// surface that reports subscription-quota consumption: every api.x.ai endpoint
// (/v1/usage, /v1/rate-limits, /v1/quota, /v1/limits) 404s, and the
// x-ratelimit-* response headers describe short per-window API buckets that sit
// at 100% remaining, not the weekly allowance.
//
// It accepts the same xAI OAuth access token the refresher already mints. It is
// an internal endpoint of the grok.com web app, not a documented API: treat any
// failure as "quota unknown" and fall back to the rate-limit header probe.
const grokCreditsEndpoint = "https://grok.com/grok_api_v2.GrokBuildBilling/GetGrokCreditsConfig"

// grokCreditsUA is sent because Cloudflare rejects requests with no User-Agent
// ("error code: 1010"). Any non-empty value is accepted — this identifies the
// caller honestly rather than impersonating a browser.
const grokCreditsUA = "oauth-token-refresher"

// xaiCreditsTimeout bounds the quota read so the caller keeps enough of its
// own deadline to still run the fallback probe if grok.com hangs.
const xaiCreditsTimeout = 4 * time.Second

// Field numbers from the grok_api_v2 descriptor shipped in the grok.com bundle:
//
//	GetGrokCreditsConfigResponse { GrokCreditsConfig config = 1; }
//	GrokCreditsConfig {
//	  float credit_usage_percent = 1;      // 0..100
//	  google.protobuf.Timestamp billing_period_end = 5;
//	  UsagePeriod current_period = 8;      // { UsagePeriodType type = 1; ... Timestamp end = 3; }
//	  bool is_unified_billing_user = 11;
//	}
//	UsagePeriodType { UNSPECIFIED = 0; MONTHLY = 1; WEEKLY = 2; }
const (
	fieldConfig            = 1
	fieldCreditUsagePct    = 1
	fieldBillingPeriodEnd  = 5
	fieldCurrentPeriod     = 8
	fieldUnifiedBilling    = 11
	fieldPeriodType        = 1
	fieldPeriodEnd         = 3
	fieldTimestampSeconds  = 1
	usagePeriodTypeMonthly = 1
	usagePeriodTypeWeekly  = 2
)

// grokCredits is the subscription-quota snapshot from grok.com.
type grokCredits struct {
	Percent    float64   // 0..100 of the allowance consumed
	PeriodType int       // usagePeriodType* constant
	ResetAt    time.Time // zero when the response carried no period end
}

// Label renders the quota window as a short bar label ("wk", "mo").
func (g grokCredits) Label() string {
	switch g.PeriodType {
	case usagePeriodTypeWeekly:
		return "wk"
	case usagePeriodTypeMonthly:
		return "mo"
	default:
		return "sub"
	}
}

// probeGrokCredits reads the subscription quota for an xAI OAuth token. It
// speaks gRPC-Web with an empty request message: a 5-byte frame header (flag
// byte + big-endian length) followed by the payload, which for an empty message
// is zero bytes.
func probeGrokCredits(ctx context.Context, accessToken string) (grokCredits, error) {
	var out grokCredits
	frame := []byte{0, 0, 0, 0, 0}
	req, err := http.NewRequestWithContext(ctx, "POST", grokCreditsEndpoint, bytes.NewReader(frame))
	if err != nil {
		return out, err
	}
	req.Header.Set("Content-Type", "application/grpc-web+proto")
	req.Header.Set("Accept", "application/grpc-web+proto")
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("User-Agent", grokCreditsUA)

	client := &http.Client{Timeout: xaiCreditsTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	// A non-2xx status means no usable answer. gRPC-Web also reports application
	// errors as a grpc-status trailer frame inside the body; grpcWebMessage skips
	// trailer frames and then errors with "no grpc-web data frame", so an error
	// reply still degrades to the caller's fallback. The header check below only
	// catches servers that emit a trailers-only response as real headers.
	if resp.StatusCode >= 400 {
		return out, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	if st := resp.Header.Get("grpc-status"); st != "" && st != "0" {
		return out, fmt.Errorf("grpc-status %s", st)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return out, err
	}
	msg, err := grpcWebMessage(body)
	if err != nil {
		return out, err
	}
	return parseGrokCredits(msg)
}

// grpcWebMessage returns the payload of the first uncompressed data frame in a
// gRPC-Web response. Frames are [flags:1][length:4][payload]; flag bit 0x80
// marks a trailer frame (not the message) and bit 0x01 marks a compressed
// payload, which this reader does not decode.
func grpcWebMessage(body []byte) ([]byte, error) {
	for len(body) >= 5 {
		flags := body[0]
		n := binary.BigEndian.Uint32(body[1:5])
		if uint64(n) > uint64(len(body)-5) {
			return nil, errors.New("truncated grpc-web frame")
		}
		payload := body[5 : 5+n]
		if flags&0x80 == 0 {
			if flags&0x01 != 0 {
				return nil, errors.New("compressed grpc-web frame")
			}
			return payload, nil
		}
		body = body[5+n:]
	}
	return nil, errors.New("no grpc-web data frame")
}

// parseGrokCredits decodes the fields this dashboard needs out of a
// GetGrokCreditsConfigResponse. Unknown fields are skipped, so upstream schema
// additions are harmless. Anything else — a dropped percent, a value outside
// the documented range, a repurposed tag — is an error, so the caller falls
// back to the rate-limit probe rather than drawing a confident wrong bar.
func parseGrokCredits(msg []byte) (grokCredits, error) {
	var out grokCredits
	cfg, err := protoBytes(msg, fieldConfig)
	if err != nil || cfg == nil {
		return out, errors.New("no credits config in response")
	}
	pct, ok, err := protoFixed32(cfg, fieldCreditUsagePct)
	if err != nil {
		return out, err
	}
	if !ok {
		return out, errors.New("no credit_usage_percent in response")
	}
	out.Percent = float64(math.Float32frombits(pct))
	// Negated comparison so NaN (which fails both) is rejected too: an
	// unvalidated percent renders as a healthy green "NaN%"/"-12%" bar.
	if !(out.Percent >= 0 && out.Percent <= 100) {
		return grokCredits{}, fmt.Errorf("credit_usage_percent %v out of range", out.Percent)
	}

	if period, err := protoBytes(cfg, fieldCurrentPeriod); err == nil && period != nil {
		if t, ok, err := protoVarint(period, fieldPeriodType); err == nil && ok {
			out.PeriodType = int(t)
		}
		if end, err := protoBytes(period, fieldPeriodEnd); err == nil && end != nil {
			out.ResetAt = timestampSeconds(end)
		}
	}
	if out.ResetAt.IsZero() {
		if end, err := protoBytes(cfg, fieldBillingPeriodEnd); err == nil && end != nil {
			out.ResetAt = timestampSeconds(end)
		}
	}
	// Only a unified-billing account has a meaningful percent — the web app
	// hides the panel otherwise. proto3 omits a false scalar entirely, so an
	// ABSENT field means "not unified", not "unknown": require presence.
	if unified, ok, err := protoVarint(cfg, fieldUnifiedBilling); err != nil || !ok || unified == 0 {
		return grokCredits{}, errors.New("account is not on unified billing")
	}
	return out, nil
}

// timestampSeconds reads the seconds field of a google.protobuf.Timestamp,
// returning the zero time when absent or implausible. The bound keeps a
// repurposed tag from rendering a confident date in 1901 or the year 292277026596.
func timestampSeconds(buf []byte) time.Time {
	secs, ok, err := protoVarint(buf, fieldTimestampSeconds)
	if err != nil || !ok || secs > math.MaxInt32 {
		return time.Time{}
	}
	t := time.Unix(int64(secs), 0).UTC()
	if t.Year() < 2020 || t.Year() > 2200 {
		return time.Time{}
	}
	return t
}

// The three protoX helpers below are a deliberately tiny wire-format reader:
// this module has no third-party dependencies and one response shape does not
// justify pulling in google.golang.org/protobuf.

// protoBytes returns the payload of the first length-delimited field with the
// given number, or nil when absent.
func protoBytes(buf []byte, field int) ([]byte, error) {
	var out []byte
	err := protoWalk(buf, func(num int, wire int, val []byte, _ uint64) bool {
		if num == field && wire == 2 {
			out = val
			return false
		}
		return true
	})
	return out, err
}

// protoVarint returns the first varint field with the given number.
func protoVarint(buf []byte, field int) (uint64, bool, error) {
	var out uint64
	var found bool
	err := protoWalk(buf, func(num int, wire int, _ []byte, v uint64) bool {
		if num == field && wire == 0 {
			out, found = v, true
			return false
		}
		return true
	})
	return out, found, err
}

// protoFixed32 returns the first fixed32 field with the given number.
func protoFixed32(buf []byte, field int) (uint32, bool, error) {
	var out uint32
	var found bool
	err := protoWalk(buf, func(num int, wire int, val []byte, _ uint64) bool {
		if num == field && wire == 5 {
			out, found = binary.LittleEndian.Uint32(val), true
			return false
		}
		return true
	})
	return out, found, err
}

// protoWalk iterates the top-level fields of a protobuf message, calling fn
// until it returns false. Length-delimited and fixed payloads arrive in val,
// varints in v.
func protoWalk(buf []byte, fn func(num, wire int, val []byte, v uint64) bool) error {
	for i := 0; i < len(buf); {
		key, n := binary.Uvarint(buf[i:])
		if n <= 0 {
			return errors.New("bad protobuf key")
		}
		i += n
		num, wire := int(key>>3), int(key&7)
		switch wire {
		case 0:
			v, n := binary.Uvarint(buf[i:])
			if n <= 0 {
				return errors.New("bad protobuf varint")
			}
			i += n
			if !fn(num, wire, nil, v) {
				return nil
			}
		case 1, 5:
			width := 8
			if wire == 5 {
				width = 4
			}
			if i+width > len(buf) {
				return errors.New("truncated protobuf fixed field")
			}
			if !fn(num, wire, buf[i:i+width], 0) {
				return nil
			}
			i += width
		case 2:
			ln, n := binary.Uvarint(buf[i:])
			if n <= 0 {
				return errors.New("bad protobuf length")
			}
			i += n
			// Compare against the remaining bytes, never i+ln: a valid 10-byte
			// Uvarint can reach 2^64-1, and uint64(i)+ln would wrap past the
			// guard and slice with a negative high bound.
			if ln > uint64(len(buf)-i) {
				return errors.New("truncated protobuf field")
			}
			if !fn(num, wire, buf[i:i+int(ln)], 0) {
				return nil
			}
			i += int(ln)
		default:
			return fmt.Errorf("unsupported protobuf wire type %d", wire)
		}
	}
	return nil
}
