package web

import "testing"

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
