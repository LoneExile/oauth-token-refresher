package oauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAPIRoot(t *testing.T) {
	cases := map[string]string{
		"https://api.x.ai/v1":        "https://api.x.ai",
		"https://api.x.ai/v1/":       "https://api.x.ai",
		"https://api.x.ai":           "https://api.x.ai",
		"https://api.anthropic.com":  "https://api.anthropic.com",
		"https://api.anthropic.com/": "https://api.anthropic.com",
		"":                           "",
	}
	for in, want := range cases {
		if got := apiRoot(in); got != want {
			t.Errorf("apiRoot(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestProberPathSingleV1 guards the regression where a base_url already ending
// in "/v1" (the xAI KV convention) produced a doubled ".../v1/v1/..." path that
// 404'd. The prober must hit exactly one versioned path regardless of whether
// the configured base carries the "/v1" suffix.
func TestProberPathSingleV1(t *testing.T) {
	cases := []struct {
		name string
		want string
	}{
		{"xai", "/v1/chat/completions"},
		{"anthropic", "/v1/messages"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var gotPath string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotPath = r.URL.Path
				w.WriteHeader(http.StatusOK)
			}))
			defer srv.Close()

			var p UsageProber
			// Configure each prober with a base_url that carries the "/v1"
			// suffix, as xAI stores it in OpenBao.
			switch c.name {
			case "xai":
				p = XAIProber{BaseURL: srv.URL + "/v1"}
			case "anthropic":
				p = AnthropicProber{BaseURL: srv.URL + "/v1"}
			}
			p.ProbeUsage(context.Background(), "tok")
			if gotPath != c.want {
				t.Errorf("%s prober hit path %q, want %q", c.name, gotPath, c.want)
			}
		})
	}
}
