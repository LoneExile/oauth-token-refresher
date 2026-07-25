package oauth

import (
	"encoding/hex"
	"testing"
	"time"
)

// liveResponse is a verbatim gRPC-Web response captured from
// grok.com/grok_api_v2.GrokBuildBilling/GetGrokCreditsConfig for a SuperGrok
// account whose Settings → Usage panel read "68% used · Resets July 27, 2026".
// It carries the data frame followed by the "grpc-status:0" trailer frame.
const liveResponse = "000000005e0a5c0d0000884212001a00220c08e4f5f7d20610a8de83a0022a0c08e4ea9cd30610a8de83a0023a07080115000088423a0208023a020804421e0802120c08e4f5f7d20610a8de83a0021a0c08e4ea9cd30610a8de83a002580162006801800000000f677270632d7374617475733a300d0a"

func decodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad fixture: %v", err)
	}
	return b
}

func TestParseGrokCreditsLiveResponse(t *testing.T) {
	msg, err := grpcWebMessage(decodeHex(t, liveResponse))
	if err != nil {
		t.Fatalf("grpcWebMessage: %v", err)
	}
	got, err := parseGrokCredits(msg)
	if err != nil {
		t.Fatalf("parseGrokCredits: %v", err)
	}
	if got.Percent != 68 {
		t.Errorf("Percent = %v, want 68", got.Percent)
	}
	if got.PeriodType != usagePeriodTypeWeekly {
		t.Errorf("PeriodType = %d, want weekly (%d)", got.PeriodType, usagePeriodTypeWeekly)
	}
	if got.Label() != "wk" {
		t.Errorf("Label = %q, want wk", got.Label())
	}
	want := time.Date(2026, 7, 27, 10, 39, 32, 0, time.UTC)
	if !got.ResetAt.Equal(want) {
		t.Errorf("ResetAt = %s, want %s", got.ResetAt, want)
	}
}

// TestGrpcWebMessageSkipsTrailerOnlyBody guards the frame walker: a response
// carrying only a trailer frame (the shape of an error reply) must not be
// mistaken for a message.
func TestGrpcWebMessageSkipsTrailerOnlyBody(t *testing.T) {
	trailerOnly := decodeHex(t, "800000000f677270632d7374617475733a300d0a")
	if _, err := grpcWebMessage(trailerOnly); err == nil {
		t.Fatal("want error for trailer-only body, got nil")
	}
	if _, err := grpcWebMessage(nil); err == nil {
		t.Fatal("want error for empty body, got nil")
	}
	if _, err := grpcWebMessage(decodeHex(t, "0000000010deadbeef")); err == nil {
		t.Fatal("want error for truncated frame, got nil")
	}
}

// TestParseGrokCreditsRejectsUnusableShapes keeps a schema change or a
// non-subscription account from rendering a bogus bar: each must error so the
// prober falls back to the rate-limit headers.
func TestParseGrokCreditsRejectsUnusableShapes(t *testing.T) {
	cases := map[string]string{
		"empty response":       "",
		"config without pct":   "0a005801",
		"explicit not unified": "0a070d000088425800",
		// proto3 omits a false scalar, so an ABSENT unified flag must also lose.
		"unified flag absent":  "0a050d00008842",
		"garbage wire type":    "0f",
		"truncated len prefix": "0a7f",
		// NaN, negative and >100 percents would otherwise paint a confident bar.
		"percent NaN":      "0a070d0000c07f5801",
		"percent negative": "0a070d0000c8c25801",
		"percent over 100": "0a070d00007a435801",
	}
	for name, h := range cases {
		if _, err := parseGrokCredits(decodeHex(t, h)); err == nil {
			t.Errorf("%s: want error, got nil", name)
		}
	}
}

// TestParseGrokCreditsFallsBackToBillingPeriodEnd covers an account whose
// response omits current_period (field 8) but still carries
// billing_period_end (field 5): 50% used, resetting at the same timestamp.
func TestParseGrokCreditsFallsBackToBillingPeriodEnd(t *testing.T) {
	// config { credit_usage_percent = 50.0; billing_period_end {...}; is_unified_billing_user = true }
	msg := decodeHex(t, "0a150d00004842"+"2a0c08e4ea9cd30610a8de83a002"+"5801")
	got, err := parseGrokCredits(msg)
	if err != nil {
		t.Fatalf("parseGrokCredits: %v", err)
	}
	if got.Percent != 50 {
		t.Errorf("Percent = %v, want 50", got.Percent)
	}
	if got.Label() != "sub" {
		t.Errorf("Label = %q, want sub (no period type)", got.Label())
	}
	want := time.Date(2026, 7, 27, 10, 39, 32, 0, time.UTC)
	if !got.ResetAt.Equal(want) {
		t.Errorf("ResetAt = %s, want %s", got.ResetAt, want)
	}
}

// TestParseGrokCreditsSurvivesHostileBytes pins the wire reader against inputs
// that must error rather than panic. The length prefix ff*9 01 is a VALID
// 10-byte Uvarint of 2^64-1: an i+ln bounds check wraps past the guard and
// slices with a negative high bound.
func TestParseGrokCreditsSurvivesHostileBytes(t *testing.T) {
	hostile := []string{
		"0affffffffffffffffff01", // length 2^64-1 (wraps an i+ln check)
		"0afeffffffffffffffff01", // length 2^64-2
		"0a80808080808080808001", // length 2^63
		"0a050dffffff",           // nested fixed32 truncated by one byte
		"0a060a80808080",         // nested length varint runs off the end
		"0aff",                   // length varint truncated
		"08",                     // key with no varint body
		"0d0000",                 // fixed32 truncated
		"0a020a00",               // well-formed but percent-less nesting
	}
	for _, h := range hostile {
		msg := decodeHex(t, h)
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("parseGrokCredits(%s) panicked: %v", h, r)
				}
			}()
			if _, err := parseGrokCredits(msg); err == nil {
				t.Errorf("parseGrokCredits(%s): want error, got nil", h)
			}
		}()
	}
}

// TestTimestampSecondsRejectsImplausible guards the reset-time note: a
// repurposed tag must leave ResetAt zero (note hidden) rather than print a
// plausible-looking date decades or millennia off.
func TestTimestampSecondsRejectsImplausible(t *testing.T) {
	if got := timestampSeconds(decodeHex(t, "0800")); !got.IsZero() {
		t.Errorf("epoch 0 = %s, want zero", got)
	}
	if got := timestampSeconds(decodeHex(t, "08ffffffffffffffff7f")); !got.IsZero() {
		t.Errorf("huge seconds = %s, want zero", got)
	}
	if got := timestampSeconds(decodeHex(t, "1001")); !got.IsZero() {
		t.Errorf("wrong field = %s, want zero", got)
	}
	if got := timestampSeconds(decodeHex(t, "08e4ea9cd306")); got.IsZero() {
		t.Error("valid seconds decoded as zero")
	}
}
