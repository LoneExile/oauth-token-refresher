package metrics

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestSnapshotAndPrometheus(t *testing.T) {
	s := NewStore([]string{"xai", "anthropic"})
	exp := time.Now().Add(time.Hour)
	s.OK("xai", exp, true)
	s.Err("anthropic", errors.New("boom"))

	snap := s.Snapshot()
	if !snap["xai"].Healthy {
		t.Error("xai should be healthy after OK")
	}
	if !snap["xai"].TokenValid {
		t.Error("xai token should be valid (future expiry)")
	}
	if snap["xai"].Cycles != 1 {
		t.Errorf("xai cycles=%d", snap["xai"].Cycles)
	}
	if snap["anthropic"].Healthy {
		t.Error("anthropic should be unhealthy after Err")
	}
	if snap["anthropic"].LastError != "boom" {
		t.Errorf("anthropic last_error=%q", snap["anthropic"].LastError)
	}
	if snap["anthropic"].Errors != 1 {
		t.Errorf("anthropic errors=%d", snap["anthropic"].Errors)
	}

	var buf bytes.Buffer
	s.WritePrometheus(&buf)
	out := buf.String()
	for _, want := range []string{
		"# TYPE oauth_refresh_cycles_total counter",
		"# TYPE oauth_refresh_success gauge",
		`oauth_refresh_cycles_total{provider="xai"} 1`,
		`oauth_refresh_cycles_total{provider="anthropic"} 1`,
		`oauth_refresh_errors_total{provider="anthropic"} 1`,
		`oauth_refresh_errors_total{provider="xai"} 0`,
		`oauth_refresh_success{provider="xai"} 1`,
		`oauth_refresh_success{provider="anthropic"} 0`,
		`oauth_refresh_token_valid{provider="xai"} 1`,
		`oauth_refresh_token_valid{provider="anthropic"} 0`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("metrics output missing %q\n---\n%s", want, out)
		}
	}
	// Timestamps must be plain integers, not scientific notation.
	if strings.Contains(out, "e+") {
		t.Errorf("metrics contain scientific notation:\n%s", out)
	}
}

func TestReadyIgnoresProviderErrors(t *testing.T) {
	s := NewStore([]string{"xai", "anthropic"})
	if !s.Ready() {
		t.Fatal("should be ready at startup")
	}
	// xAI healthy, anthropic failing (unseeded / forbidden) — pod stays ready so
	// the login UI used to seed anthropic remains reachable.
	s.OK("xai", time.Now().Add(time.Hour), true)
	s.Err("anthropic", errors.New("permission denied"))
	if !s.Ready() {
		t.Fatal("one failing provider must not take the pod out of service")
	}
}

func TestExpiredTokenNotValid(t *testing.T) {
	s := NewStore([]string{"xai"})
	s.OK("xai", time.Now().Add(-time.Minute), false)
	if s.Snapshot()["xai"].TokenValid {
		t.Error("past expiry => token not valid")
	}
	var buf bytes.Buffer
	s.WritePrometheus(&buf)
	if !strings.Contains(buf.String(), `oauth_refresh_token_valid{provider="xai"} 0`) {
		t.Errorf("expected token_valid 0:\n%s", buf.String())
	}
}
