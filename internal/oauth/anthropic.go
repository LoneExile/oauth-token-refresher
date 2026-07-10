package oauth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Anthropic OAuth constants, matching OMP's Claude Pro/Max login flow.
const (
	// AnthropicTokenURL is the fixed token endpoint (no OIDC discovery).
	AnthropicTokenURL = "https://api.anthropic.com/v1/oauth/token"
	// AnthropicAuthorizeURL is the browser authorization endpoint.
	AnthropicAuthorizeURL = "https://claude.ai/oauth/authorize"
	// AnthropicClientID is OMP's public Claude Pro/Max OAuth client ID.
	AnthropicClientID = "9d1c250a-e61b-44d9-88ed-5944d1962f5e"
	// AnthropicBaseURL is the native Anthropic API base written to KV as base_url.
	AnthropicBaseURL = "https://api.anthropic.com"
	// AnthropicScope is the OAuth scope OMP requests for Claude Pro/Max login.
	AnthropicScope = "org:create_api_key user:profile user:inference user:sessions:claude_code user:mcp_servers user:file_upload"
	// AnthropicRedirectURI is the registered loopback redirect used by the
	// out-of-band paste flow. It must match what the client has registered.
	AnthropicRedirectURI = "http://localhost:54545/callback"

	anthropicBetaHeader = "oauth-2025-04-20"
	anthropicUserAgent  = "anthropic-sdk-typescript/0.94.0 userOAuthProvider"
)

// AnthropicClient refreshes Claude Pro/Max OAuth tokens. Unlike xAI, Anthropic
// uses a fixed token endpoint, a JSON request body, and requires the
// `anthropic-beta` header to accept the OAuth grant.
type AnthropicClient struct {
	TokenURL     string
	ClientID     string
	AuthorizeURL string
	Scope        string
	Redirect     string
	HTTP         *http.Client
}

// NewAnthropic builds an Anthropic refresher. Empty tokenURL/clientID fall back
// to the OMP defaults.
func NewAnthropic(tokenURL, clientID string) *AnthropicClient {
	if tokenURL == "" {
		tokenURL = AnthropicTokenURL
	}
	if clientID == "" {
		clientID = AnthropicClientID
	}
	return &AnthropicClient{
		TokenURL:     tokenURL,
		ClientID:     clientID,
		AuthorizeURL: AnthropicAuthorizeURL,
		Scope:        AnthropicScope,
		Redirect:     AnthropicRedirectURI,
		HTTP:         &http.Client{Timeout: 30 * time.Second},
	}
}

// Refresh exchanges refresh_token for a new access token (and rotated refresh).
func (c *AnthropicClient) Refresh(ctx context.Context, refreshToken string) (Credential, error) {
	reqBody, err := json.Marshal(map[string]string{
		"grant_type":    "refresh_token",
		"client_id":     c.ClientID,
		"refresh_token": refreshToken,
	})
	if err != nil {
		return Credential{}, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.TokenURL, bytes.NewReader(reqBody))
	if err != nil {
		return Credential{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("anthropic-beta", anthropicBetaHeader)
	req.Header.Set("User-Agent", anthropicUserAgent)

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return Credential{}, fmt.Errorf("token refresh: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return Credential{}, fmt.Errorf("token refresh: status %d: %s", resp.StatusCode, truncate(body, 400))
	}
	var tr TokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return Credential{}, err
	}
	if tr.AccessToken == "" || tr.ExpiresIn <= 0 {
		return Credential{}, fmt.Errorf("token refresh: missing access_token/expires_in")
	}
	return credentialFrom(tr, refreshToken), nil
}

// RedirectURI returns the redirect URI sent in the authorize + exchange requests.
func (c *AnthropicClient) RedirectURI() string { return c.Redirect }

// AuthURL builds the Claude authorization URL. code=true makes Claude display
// the authorization code for out-of-band paste.
func (c *AnthropicClient) AuthURL(pkce PKCE, state string) string {
	q := url.Values{}
	q.Set("code", "true")
	q.Set("client_id", c.ClientID)
	q.Set("response_type", "code")
	q.Set("redirect_uri", c.Redirect)
	q.Set("scope", c.Scope)
	q.Set("code_challenge", pkce.Challenge)
	q.Set("code_challenge_method", "S256")
	q.Set("state", state)
	return c.AuthorizeURL + "?" + q.Encode()
}

// ExchangeCode trades an authorization code for a Credential. A `code#state`
// paste carries the returned state in its fragment, overriding the argument.
func (c *AnthropicClient) ExchangeCode(ctx context.Context, code, state string, pkce PKCE) (Credential, error) {
	if i := strings.IndexByte(code, '#'); i >= 0 {
		if frag := code[i+1:]; frag != "" {
			state = frag
		}
		code = code[:i]
	}
	code = strings.TrimSpace(code)
	reqBody, err := json.Marshal(map[string]string{
		"grant_type":    "authorization_code",
		"client_id":     c.ClientID,
		"code":          code,
		"state":         state,
		"redirect_uri":  c.Redirect,
		"code_verifier": pkce.Verifier,
	})
	if err != nil {
		return Credential{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.TokenURL, bytes.NewReader(reqBody))
	if err != nil {
		return Credential{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return Credential{}, fmt.Errorf("code exchange: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return Credential{}, fmt.Errorf("code exchange: status %d: %s", resp.StatusCode, truncate(body, 400))
	}
	var tr TokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return Credential{}, err
	}
	if tr.AccessToken == "" || tr.RefreshToken == "" || tr.ExpiresIn <= 0 {
		return Credential{}, fmt.Errorf("code exchange: missing access/refresh/expires_in")
	}
	return credentialFrom(tr, ""), nil
}
