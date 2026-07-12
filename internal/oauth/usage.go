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
// Values come from the anthropic-ratelimit-* / x-ratelimit-* response headers.
type Usage struct {
	// RequestsRemaining / TokensRemaining are the most useful "how much is left"
	// numbers. Empty string means the header was absent (provider doesn't report it).
	RequestsRemaining string
	RequestsLimit     string
	TokensRemaining   string
	TokensLimit       string
	// ResetAt is when the current rate-limit window resets (RFC 3339 from the API).
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

// ProbeUsage is a no-op prober for providers that don't support usage probing.
// Returns an empty Usage (no headers, no error).
type NoOpProber struct{}

func (NoOpProber) ProbeUsage(context.Context, string) Usage { return Usage{} }

// AnthropicProber probes the Anthropic Messages API for rate-limit headers.
// Uses a minimal request: model=claude-haiku-4-5, max_tokens=1, a 1-word prompt.
type AnthropicProber struct {
	BaseURL string // e.g. "https://api.anthropic.com"
}

// XAIProber probes the xAI Grok API for rate-limit headers.
type XAIProber struct {
	BaseURL string // e.g. "https://api.x.ai"
}

// ProbeUsage makes a minimal Anthropic Messages API call and reads the
// anthropic-ratelimit-* headers from the response.
func (p AnthropicProber) ProbeUsage(ctx context.Context, accessToken string) Usage {
	base := p.BaseURL
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
	base := p.BaseURL
	if base == "" {
		base = "https://api.x.ai"
	}
	body := `{"model":"grok-3-mini","max_tokens":1,"messages":[{"role":"user","content":"hi"}]}`
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
	u.RequestsRemaining = h.Get("anthropic-ratelimit-requests-remaining")
	u.RequestsLimit = h.Get("anthropic-ratelimit-requests-limit")
	u.TokensRemaining = h.Get("anthropic-ratelimit-tokens-remaining")
	u.TokensLimit = h.Get("anthropic-ratelimit-tokens-limit")
	u.ResetAt = h.Get("anthropic-ratelimit-tokens-reset")
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
	// xAI uses x-ratelimit-* headers
	u.RequestsRemaining = h.Get("x-ratelimit-remaining-requests")
	u.RequestsLimit = h.Get("x-ratelimit-limit-requests")
	u.TokensRemaining = h.Get("x-ratelimit-remaining-tokens")
	u.TokensLimit = h.Get("x-ratelimit-limit-tokens")
	u.ResetAt = h.Get("x-ratelimit-reset")
	return u
}

// UsagePercent computes a 0-100 integer for "how much is left" from the
// remaining and limit strings. Returns -1 if either is empty or unparseable.
func UsagePercent(remaining, limit string) int {
	if remaining == "" || limit == "" {
		return -1
	}
	r, err1 := strconv.ParseFloat(remaining, 64)
	l, err2 := strconv.ParseFloat(limit, 64)
	if err1 != nil || err2 != nil || l <= 0 {
		return -1
	}
	pct := int(r / l * 100)
	if pct < 0 {
		pct = 0
	}
	if pct > 100 {
		pct = 100
	}
	return pct
}
