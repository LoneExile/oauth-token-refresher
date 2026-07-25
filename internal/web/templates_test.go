package web

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/LoneExile/oauth-token-refresher/internal/oauth"
)

func TestUsedFrac(t *testing.T) {
	cases := []struct {
		rem, lim string
		want     string
	}{
		{"10000000", "10000000", "0.0000"}, // nothing used
		{"0", "10000000", "1.0000"},        // fully used
		{"5000000", "10000000", "0.5000"},  // half used
		{"480", "480", "0.0000"},
		{"120", "480", "0.7500"},
		{"", "480", "0"},         // unparseable remaining
		{"100", "", "0"},         // unparseable limit
		{"100", "0", "0"},        // non-positive limit
		{"200", "100", "0.0000"}, // remaining > limit clamps to 0 used
	}
	for _, c := range cases {
		if got := usedFrac(c.rem, c.lim); got != c.want {
			t.Errorf("usedFrac(%q,%q) = %q, want %q", c.rem, c.lim, got, c.want)
		}
	}
}

// TestUsedFracFeedsUtilHelpers verifies the fraction usedFrac emits is consumed
// correctly by the same helpers Anthropic bars use, so xAI and Anthropic render
// with identical fill/percent semantics (fill = consumed).
func TestUsedFracFeedsUtilHelpers(t *testing.T) {
	u := usedFrac("120", "480") // 75% used
	if got := utilBar(u); got != "75" {
		t.Errorf("utilBar = %q, want 75", got)
	}
	if got := utilPct(u); got != "75" {
		t.Errorf("utilPct = %q, want 75", got)
	}
	if got := utilColor(u); got != "quota-warn" {
		t.Errorf("utilColor = %q, want quota-warn", got)
	}
}

func TestCompact(t *testing.T) {
	cases := []struct{ in, want string }{
		{"15000000", "15M"},
		{"14300000", "14.3M"},
		{"53000000", "53M"},
		{"15000", "15k"},
		{"8300", "8300"}, // below the 10k threshold: raw digits stay readable
		{"900", "900"},
		{"0", "0"},
		{"", ""},       // unparseable: passed through
		{"n/a", "n/a"}, // unparseable: passed through
	}
	for _, c := range cases {
		if got := compact(c.in); got != c.want {
			t.Errorf("compact(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestDashboardQuotaBranches pins the mutually exclusive quota rows in the
// dashboard template: which signal wins when several are present, and that the
// rate-limit counters render as two independent rows rather than one.
func TestDashboardQuotaBranches(t *testing.T) {
	cases := []struct {
		name string
		u    oauth.Usage
		want []string
		deny []string
	}{
		{
			name: "error shadows every bar",
			u:    oauth.Usage{Err: "HTTP 401", QuotaUtil: "0.6800", Window7dUtil: "0.10"},
			want: []string{"HTTP 401"},
			deny: []string{">wk<", ">7d<"},
		},
		{
			name: "subscription quota outranks utilization windows",
			u:    oauth.Usage{QuotaUtil: "0.6800", QuotaLabel: "wk", QuotaReset: "Jul 27 2026 10:39 UTC", Window7dUtil: "0.10"},
			want: []string{">wk<", "68%", "resets Jul 27 2026 10:39 UTC"},
			deny: []string{">7d<", "not subscription quota"},
		},
		{
			name: "quota without a reset time hides the note",
			u:    oauth.Usage{QuotaUtil: "0.0500", QuotaLabel: "mo"},
			want: []string{">mo<", "5%"},
			deny: []string{"resets"},
		},
		{
			name: "anthropic windows still render both bars",
			u:    oauth.Usage{Window7dUtil: "0.94", Window5hUtil: "0.07", Status: "allowed_warning"},
			want: []string{">7d<", "94%", ">5h<", "7%", "warning"},
			deny: []string{">wk<"},
		},
		{
			name: "token and request counters render as separate rows",
			u:    oauth.Usage{TokensRemaining: "15000000", TokensLimit: "15000000", RequestsRemaining: "450", RequestsLimit: "900"},
			want: []string{">tok<", "15M/15M", ">req<", "450/900", "50%", "not subscription quota"},
			deny: []string{">wk<", ">7d<"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var buf bytes.Buffer
			view := []ProviderView{{
				Name:     "xai",
				Kind:     "device",
				ActiveID: "default",
				Accounts: []AccountView{{
					ID: "default", Label: "default", Active: true, Seeded: true,
					TokenValid: true, Expiry: time.Now().Add(time.Hour), Usage: c.u,
				}},
			}}
			if err := tmpl.ExecuteTemplate(&buf, "dashboard", view); err != nil {
				t.Fatalf("execute: %v", err)
			}
			got := buf.String()
			for _, w := range c.want {
				if !strings.Contains(got, w) {
					t.Errorf("missing %q in:\n%s", w, got)
				}
			}
			for _, d := range c.deny {
				if strings.Contains(got, d) {
					t.Errorf("unexpected %q in:\n%s", d, got)
				}
			}
		})
	}
}
