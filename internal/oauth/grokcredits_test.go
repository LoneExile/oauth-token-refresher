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
// non-subscription account from rendering a bogus 0% bar: both must error so
// the prober falls back to the rate-limit headers.
func TestParseGrokCreditsRejectsUnusableShapes(t *testing.T) {
	cases := map[string]string{
		"empty response":       "",
		"config without pct":   "0a0058 01",
		"not unified billing":  "0a070d000088425800",
		"garbage wire type":    "0f",
		"truncated len prefix": "0a7f",
	}
	for name, h := range cases {
		clean := ""
		for _, r := range h {
			if r != ' ' {
				clean += string(r)
			}
		}
		if _, err := parseGrokCredits(decodeHex(t, clean)); err == nil {
			t.Errorf("%s: want error, got nil", name)
		}
	}
}

// TestParseGrokCreditsFallsBackToBillingPeriodEnd covers an account whose
// response omits current_period (field 8) but still carries
// billing_period_end (field 5): 50% used, resetting at the same timestamp.
func TestParseGrokCreditsFallsBackToBillingPeriodEnd(t *testing.T) {
	// config { credit_usage_percent = 50.0; billing_period_end { seconds } }
	msg := decodeHex(t, "0a130d00004842"+"2a0c08e4ea9cd30610a8de83a002")
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
