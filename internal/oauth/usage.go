package oauth

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Usage is the rate-limit usage snapshot from a lightweight API probe.
// Anthropic OAuth subscription tokens return utilization-based headers
// (anthropic-ratelimit-unified-5h-utilization, -7d-utilization) while API-key
// providers return remaining/limit counts. Both are surfaced here.
type Usage struct {
	// API-key style: remaining/limit counts (xAI, Anthropic API keys)
	RequestsRemaining string
	RequestsLimit     string
	TokensRemaining   string
	TokensLimit       string
	// Anthropic OAuth subscription style: utilization 0.0-1.0
	Window5hUtil  string // anthropic-ratelimit-unified-5h-utilization
	Window7dUtil  string // anthropic-ratelimit-unified-7d-utilization
	Window5hReset string // unix timestamp
	Window7dReset string // unix timestamp
	// Status: "allowed", "allowed_warning", "blocked"
	Status string
	// ResetAt is when the current rate-limit window resets.
	ResetAt string
	// Err is non-empty if the probe failed (e.g. 429, 401, network error).
	Err string
}

// UsageProber makes a lightweight API call with an access token to read
// rate-limit headers from the response. The call uses max_tokens=1 to minimize
// quota consumption.
type UsageProber interface {
	ProbeUsage(ctx context.Context, accessToken string) Usage
}

// NoOpProber is a no-op prober for providers that don't support usage probing.
type NoOpProber struct{}

func (NoOpProber) ProbeUsage(context.Context, string) Usage { return Usage{} }

// AnthropicProber probes the Anthropic Messages API for rate-limit headers.
// OAuth subscription tokens (sk-ant-oat*) return anthropic-ratelimit-unified-*
// headers with 5h/7d utilization windows.
type AnthropicProber struct {
	BaseURL string // e.g. "https://api.anthropic.com"
}

// XAIProber probes the xAI Grok API for rate-limit headers.
type XAIProber struct {
	BaseURL string // e.g. "https://api.x.ai"
}

// apiRoot normalizes a provider base URL to the host root by trimming a trailing
// slash and a trailing "/v1" segment, so ProbeUsage can safely append the
// versioned path (e.g. "/v1/chat/completions"). The KV base_url convention
// differs per provider — xAI stores ".../v1" while Anthropic stores the bare
// host — and without this the xAI probe hit ".../v1/v1/..." and 404'd.
func apiRoot(base string) string {
	base = strings.TrimRight(base, "/")
	return strings.TrimSuffix(base, "/v1")
}

// ProbeUsage makes a minimal Anthropic Messages API call and reads the
// anthropic-ratelimit-unified-* headers from the response.
func (p AnthropicProber) ProbeUsage(ctx context.Context, accessToken string) Usage {
	base := apiRoot(p.BaseURL)
	if base == "" {
		base = AnthropicBaseURL
	}
	body := `{"model":"claude-haiku-4-5","max_tokens":1,"messages":[{"role":"user","content":"hi"}]}`
	req, err := http.NewRequestWithContext(ctx, "POST", base+"/v1/messages", strings.NewReader(body))
	if err != nil {
		return Usage{Err: err.Error()}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("anthropic-version", "2023-06-01")
	req.Header.Set("anthropic-beta", anthropicBetaHeader)
	req.Header.Set("User-Agent", anthropicUserAgent)

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return Usage{Err: err.Error()}
	}
	defer resp.Body.Close()

	return parseAnthropicHeaders(resp.Header, resp.StatusCode)
}

// ProbeUsage makes a minimal xAI Grok API call and reads rate-limit headers.
func (p XAIProber) ProbeUsage(ctx context.Context, accessToken string) Usage {
	base := apiRoot(p.BaseURL)
	if base == "" {
		base = "https://api.x.ai"
	}
	body := `{"model":"grok-4.20-non-reasoning-latest","max_tokens":1,"messages":[{"role":"user","content":"hi"}]}`
	req, err := http.NewRequestWithContext(ctx, "POST", base+"/v1/chat/completions", strings.NewReader(body))
	if err != nil {
		return Usage{Err: err.Error()}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return Usage{Err: err.Error()}
	}
	defer resp.Body.Close()

	return parseXAIHeaders(resp.Header, resp.StatusCode)
}

// parseAnthropicHeaders extracts rate-limit values from Anthropic response headers.
// OAuth subscription tokens return anthropic-ratelimit-unified-* headers with
// utilization (0.0-1.0) for 5h and 7d windows. API keys return
// anthropic-ratelimit-tokens-remaining etc.
func parseAnthropicHeaders(h http.Header, status int) Usage {
	u := Usage{}
	if status == 429 {
		u.Err = "rate limited (429)"
		u.RequestsRemaining = "0"
		u.ResetAt = h.Get("retry-after")
		return u
	}
	if status >= 400 {
		u.Err = fmt.Sprintf("HTTP %d", status)
		return u
	}
	// OAuth subscription headers (unified-*)
	u.Status = h.Get("anthropic-ratelimit-unified-status")
	u.Window5hUtil = h.Get("anthropic-ratelimit-unified-5h-utilization")
	u.Window7dUtil = h.Get("anthropic-ratelimit-unified-7d-utilization")
	u.Window5hReset = h.Get("anthropic-ratelimit-unified-5h-reset")
	u.Window7dReset = h.Get("anthropic-ratelimit-unified-7d-reset")
	u.ResetAt = h.Get("anthropic-ratelimit-unified-reset")
	// API-key style headers (if present, fill those too)
	u.RequestsRemaining = h.Get("anthropic-ratelimit-requests-remaining")
	u.RequestsLimit = h.Get("anthropic-ratelimit-requests-limit")
	u.TokensRemaining = h.Get("anthropic-ratelimit-tokens-remaining")
	u.TokensLimit = h.Get("anthropic-ratelimit-tokens-limit")
	return u
}

// parseXAIHeaders extracts rate-limit values from xAI response headers.
func parseXAIHeaders(h http.Header, status int) Usage {
	u := Usage{}
	if status == 429 {
		u.Err = "rate limited (429)"
		u.RequestsRemaining = "0"
		return u
	}
	if status >= 400 {
		u.Err = fmt.Sprintf("HTTP %d", status)
		return u
	}
	u.RequestsRemaining = h.Get("x-ratelimit-remaining-requests")
	u.RequestsLimit = h.Get("x-ratelimit-limit-requests")
	u.TokensRemaining = h.Get("x-ratelimit-remaining-tokens")
	u.TokensLimit = h.Get("x-ratelimit-limit-tokens")
	u.ResetAt = h.Get("x-ratelimit-reset")
	return u
}

// UtilPercent converts a utilization string (0.0-1.0) to a 0-100 integer
// representing how much of the quota has been USED. Returns -1 if unparseable.
func UtilPercent(util string) int {
	if util == "" {
		return -1
	}
	f, err := strconv.ParseFloat(util, 64)
	if err != nil || f < 0 {
		return -1
	}
	pct := int(f * 100)
	if pct > 100 {
		pct = 100
	}
	return pct
}
