package oauth

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// OpenAI Codex (ChatGPT OAuth) constants, matching OMP's `openai-codex` login
// flow (pi-ai registry/oauth/openai-codex.ts).
//
// Codex has two upstream login flows and only one of them is usable from a
// server: the browser flow demands a local callback listener on the fixed port
// 1455 (OpenAI's redirect allowlist holds exactly
// http://localhost:1455/auth/callback), which would have to run in the browser
// of whoever is logging in — not in this process. So this client implements the
// DEVICE flow, which needs no listener.
//
// That device flow is NOT RFC 8628: it is OpenAI's own /api/accounts/deviceauth
// pair. `usercode` returns a device_auth_id + user_code, polling takes BOTH
// (which is why DeviceLogin.PollDevice receives the whole DeviceAuth), and a
// completed poll returns an authorization code plus the PKCE verifier OpenAI
// minted server-side — that pair is then exchanged at the normal token
// endpoint. Verified against OMP's flow 2026-09-10.
const (
	// OpenAICodexAuthBase hosts every OAuth endpoint (token + deviceauth).
	OpenAICodexAuthBase = "https://auth.openai.com"
	// OpenAICodexClientID is the public Codex CLI OAuth client ID.
	OpenAICodexClientID = "app_EMoamEEZ73f0CkXaXp7hrann"
	// OpenAICodexBaseURL is the ChatGPT backend written to KV as base_url.
	// Consumers append the Codex path (/codex/responses) themselves, and read
	// the required `chatgpt-account-id` out of the access token's JWT claim
	// (see codexAccountID) — it is not stored separately.
	OpenAICodexBaseURL = "https://chatgpt.com/backend-api"

	openAICodexTokenPath       = "/oauth/token"
	openAICodexUserCodePath    = "/api/accounts/deviceauth/usercode"
	openAICodexDeviceTokenPath = "/api/accounts/deviceauth/token"
	// openAICodexRedirectPath is the redirect_uri the device-code exchange must
	// present. It is registered upstream, not a real listener.
	openAICodexRedirectPath = "/deviceauth/callback"
	// openAICodexVerifyPath is the page where the user enters the user code.
	openAICodexVerifyPath = "/codex/device"

	// openAICodexDeviceTTL bounds one device login: the usercode response
	// carries no expiry (OMP instead stops after 120 polls, ≈10 min), so the
	// deadline shown to the UI is ours.
	openAICodexDeviceTTL = 10 * time.Minute
	// openAICodexPollMargin pads the server's poll interval. Pending polls
	// answer 403/404 rather than `authorization_pending`, so an under-eager
	// loop looks exactly like an auth failure from the outside; OMP adds the
	// same 3s.
	openAICodexPollMargin = 3 * time.Second

	// openAICodexUsagePath is the ChatGPT account usage endpoint, relative to
	// the /backend-api root. A GET costs no tokens, unlike the completion
	// probes the other providers need.
	openAICodexUsagePath = "/wham/usage"

	// openAICodexUserAgent identifies the refresher to the ChatGPT backend.
	openAICodexUserAgent = "oauth-token-refresher"
)

// OpenAICodexClient logs in and refreshes ChatGPT (Codex) OAuth tokens. It
// implements DeviceLogin and Refresher.
type OpenAICodexClient struct {
	AuthBase string
	ClientID string
	HTTP     *http.Client
}

// NewOpenAICodex builds a Codex refresher. Empty authBase/clientID fall back to
// the Codex CLI defaults.
func NewOpenAICodex(authBase, clientID string) *OpenAICodexClient {
	if authBase == "" {
		authBase = OpenAICodexAuthBase
	}
	if clientID == "" {
		clientID = OpenAICodexClientID
	}
	return &OpenAICodexClient{
		AuthBase: strings.TrimRight(authBase, "/"),
		ClientID: clientID,
		HTTP:     &http.Client{Timeout: 30 * time.Second},
	}
}

func (c *OpenAICodexClient) tokenURL() string       { return c.AuthBase + openAICodexTokenPath }
func (c *OpenAICodexClient) userCodeURL() string    { return c.AuthBase + openAICodexUserCodePath }
func (c *OpenAICodexClient) deviceTokenURL() string { return c.AuthBase + openAICodexDeviceTokenPath }
func (c *OpenAICodexClient) redirectURI() string    { return c.AuthBase + openAICodexRedirectPath }

// Refresh exchanges refresh_token for a new access token. OpenAI rotates the
// refresh token on every exchange; credentialFrom carries the old one forward if
// a response ever omits it.
func (c *OpenAICodexClient) Refresh(ctx context.Context, refreshToken string) (Credential, error) {
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("client_id", c.ClientID)
	form.Set("refresh_token", refreshToken)

	tr, err := c.postToken(ctx, form)
	if err != nil {
		return Credential{}, fmt.Errorf("token refresh: %w", err)
	}
	if tr.AccessToken == "" || tr.ExpiresIn <= 0 {
		return Credential{}, fmt.Errorf("token refresh: missing access_token/expires_in")
	}
	return credentialFrom(tr, refreshToken), nil
}

type codexDeviceResp struct {
	DeviceAuthID string    `json:"device_auth_id"`
	UserCode     string    `json:"user_code"`
	Interval     FlexInt64 `json:"interval"` // seconds; OpenAI sends it as a string
}

// StartDevice requests a device authorization. The returned DeviceCode is
// OpenAI's device_auth_id; polling needs the user code as well, so both travel
// in the DeviceAuth.
func (c *OpenAICodexClient) StartDevice(ctx context.Context) (DeviceAuth, error) {
	body, err := c.postJSON(ctx, c.userCodeURL(), map[string]string{"client_id": c.ClientID})
	if err != nil {
		return DeviceAuth{}, fmt.Errorf("device-code request: %w", err)
	}
	var dr codexDeviceResp
	if err := json.Unmarshal(body, &dr); err != nil {
		return DeviceAuth{}, err
	}
	if dr.DeviceAuthID == "" || dr.UserCode == "" {
		return DeviceAuth{}, fmt.Errorf("device-code response missing device_auth_id/user_code")
	}
	interval := time.Duration(dr.Interval.Int64())*time.Second + openAICodexPollMargin
	if interval < time.Second {
		interval = 5*time.Second + openAICodexPollMargin
	}
	return DeviceAuth{
		DeviceCode:              dr.DeviceAuthID,
		UserCode:                dr.UserCode,
		VerificationURIComplete: c.AuthBase + openAICodexVerifyPath,
		Interval:                interval,
		ExpiresAt:               time.Now().Add(openAICodexDeviceTTL),
	}, nil
}

type codexDevicePoll struct {
	AuthorizationCode string `json:"authorization_code"`
	CodeVerifier      string `json:"code_verifier"`
}

// PollDevice polls the deviceauth token endpoint once. A pending authorization
// answers 403/404 (OpenAI does not use the RFC 8628 error codes), and a
// completed one hands back an authorization code + the server-side PKCE
// verifier, which this exchanges for the credential before returning.
func (c *OpenAICodexClient) PollDevice(ctx context.Context, auth DeviceAuth) (Credential, PollStatus, error) {
	req := map[string]string{"device_auth_id": auth.DeviceCode, "user_code": auth.UserCode}
	body, status, err := c.doJSON(ctx, c.deviceTokenURL(), req)
	if err != nil {
		return Credential{}, PollPending, fmt.Errorf("device poll: %w", err)
	}
	if status == http.StatusForbidden || status == http.StatusNotFound {
		return Credential{}, PollPending, nil
	}
	if status != http.StatusOK {
		return Credential{}, PollPending, fmt.Errorf("device poll: status %d: %s", status, truncate(body, 200))
	}
	var pd codexDevicePoll
	if err := json.Unmarshal(body, &pd); err != nil {
		return Credential{}, PollPending, err
	}
	if pd.AuthorizationCode == "" || pd.CodeVerifier == "" {
		return Credential{}, PollPending, fmt.Errorf("device poll: response missing authorization_code/code_verifier")
	}
	cred, err := c.exchangeCode(ctx, pd.AuthorizationCode, pd.CodeVerifier)
	if err != nil {
		return Credential{}, PollPending, err
	}
	return cred, PollComplete, nil
}

// exchangeCode trades the device flow's authorization code + PKCE verifier for
// a credential.
func (c *OpenAICodexClient) exchangeCode(ctx context.Context, code, verifier string) (Credential, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", c.ClientID)
	form.Set("code", code)
	form.Set("code_verifier", verifier)
	form.Set("redirect_uri", c.redirectURI())

	tr, err := c.postToken(ctx, form)
	if err != nil {
		return Credential{}, fmt.Errorf("code exchange: %w", err)
	}
	if tr.AccessToken == "" || tr.RefreshToken == "" || tr.ExpiresIn <= 0 {
		return Credential{}, fmt.Errorf("code exchange: missing access/refresh/expires_in")
	}
	return credentialFrom(tr, ""), nil
}

// postToken POSTs a form-encoded grant to the token endpoint.
func (c *OpenAICodexClient) postToken(ctx context.Context, form url.Values) (TokenResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.tokenURL(), strings.NewReader(form.Encode()))
	if err != nil {
		return TokenResponse{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return TokenResponse{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return TokenResponse{}, fmt.Errorf("status %d: %s", resp.StatusCode, truncate(body, 400))
	}
	var tr TokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return TokenResponse{}, err
	}
	return tr, nil
}

// postJSON POSTs a JSON body and fails on any non-200.
func (c *OpenAICodexClient) postJSON(ctx context.Context, url string, payload any) ([]byte, error) {
	body, status, err := c.doJSON(ctx, url, payload)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("status %d: %s", status, truncate(body, 400))
	}
	return body, nil
}

// doJSON POSTs a JSON body and returns the (capped) body + status, leaving
// status interpretation to the caller (the device poll needs 403/404).
func (c *OpenAICodexClient) doJSON(ctx context.Context, url string, payload any) ([]byte, int, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return out, resp.StatusCode, nil
}

// codexAccountID reads chatgpt_account_id from the access token's JWT claim.
// The ChatGPT backend scopes usage (and inference) per workspace, so the id is
// sent as `ChatGPT-Account-Id`. Returns "" for anything unparseable — the
// header is then omitted rather than sent empty.
func codexAccountID(accessToken string) string {
	parts := strings.Split(accessToken, ".")
	if len(parts) < 2 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims struct {
		Auth struct {
			AccountID string `json:"chatgpt_account_id"`
		} `json:"https://api.openai.com/auth"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return ""
	}
	return claims.Auth.AccountID
}

// CodexProber reports the ChatGPT subscription usage windows. Unlike the xAI /
// Anthropic probes it burns no tokens: /wham/usage is a plain GET that returns
// the same used_percent numbers the Codex CLI shows.
type CodexProber struct {
	BaseURL string // e.g. "https://chatgpt.com/backend-api"
}

type codexUsageWindow struct {
	UsedPercent       float64 `json:"used_percent"`
	LimitWindowSecs   int64   `json:"limit_window_seconds"`
	ResetAfterSeconds int64   `json:"reset_after_seconds"`
	ResetAt           int64   `json:"reset_at"`
}

type codexRateLimit struct {
	Allowed      *bool             `json:"allowed"`
	LimitReached *bool             `json:"limit_reached"`
	Primary      *codexUsageWindow `json:"primary_window"`
	Secondary    *codexUsageWindow `json:"secondary_window"`
}

type codexUsagePayload struct {
	PlanType  string          `json:"plan_type"`
	RateLimit *codexRateLimit `json:"rate_limit"`
}

// codexUsageRoot normalizes a Codex base URL to the /backend-api root that
// /wham/usage lives under. The account endpoints are NOT part of the
// /codex/responses surface, so a base_url carrying that path (or any other
// host) must not be used verbatim — mirroring OMP's normalizeCodexBaseUrl.
func codexUsageRoot(base string) string {
	trimmed := strings.TrimRight(strings.TrimSpace(base), "/")
	if trimmed == "" {
		return OpenAICodexBaseURL
	}
	u, err := url.Parse(trimmed)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return OpenAICodexBaseURL
	}
	switch strings.ToLower(u.Hostname()) {
	case "chatgpt.com", "chat.openai.com":
		return u.Scheme + "://" + u.Host + "/backend-api"
	}
	// A test server or self-hosted proxy: keep the given root as-is.
	return trimmed
}

// ProbeUsage GETs /wham/usage and maps the primary/secondary windows onto the
// utilization fields. For ChatGPT Plus/Pro those windows are the 5h and weekly
// limits, which is why they render under the shared 5h/7d bars.
func (p CodexProber) ProbeUsage(ctx context.Context, accessToken string) Usage {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, codexUsageRoot(p.BaseURL)+openAICodexUsagePath, nil)
	if err != nil {
		return Usage{Err: err.Error()}
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("User-Agent", openAICodexUserAgent)
	if id := codexAccountID(accessToken); id != "" {
		req.Header.Set("ChatGPT-Account-Id", id)
	}

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return Usage{Err: err.Error()}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return Usage{Err: fmt.Sprintf("HTTP %d", resp.StatusCode)}
	}
	var payload codexUsagePayload
	if err := json.Unmarshal(body, &payload); err != nil {
		return Usage{Err: "usage parse error"}
	}
	return codexUsage(payload, time.Now())
}

// codexUsage maps a usage payload onto the shared Usage shape.
func codexUsage(payload codexUsagePayload, now time.Time) Usage {
	rl := payload.RateLimit
	if rl == nil {
		return Usage{Err: "usage response carried no rate_limit"}
	}
	u := Usage{}
	u.Window5hUtil, u.Window5hReset = codexWindowFields(rl.Primary, now)
	u.Window7dUtil, u.Window7dReset = codexWindowFields(rl.Secondary, now)
	switch {
	case rl.Allowed != nil && !*rl.Allowed:
		u.Status = "blocked"
	case rl.LimitReached != nil && *rl.LimitReached:
		u.Status = "rejected"
	}
	// No window at all means the probe told us nothing usable; say so rather
	// than render empty bars that read like a fresh quota.
	if u.Window5hUtil == "" && u.Window7dUtil == "" {
		u.Err = "usage response carried no window"
	}
	return u
}

// codexWindowFields converts one window into a 0.0-1.0 utilization string and a
// unix-seconds reset stamp. used_percent arrives as 0-100.
func codexWindowFields(w *codexUsageWindow, now time.Time) (util, reset string) {
	if w == nil {
		return "", ""
	}
	frac := w.UsedPercent / 100
	if frac < 0 {
		frac = 0
	}
	if frac > 1 {
		frac = 1
	}
	switch {
	case w.ResetAt > 0:
		// Seconds or milliseconds, same as OMP's resolveResetTime.
		secs := w.ResetAt
		if secs > 1e12 {
			secs /= 1000
		}
		reset = fmt.Sprintf("%d", secs)
	case w.ResetAfterSeconds > 0:
		reset = fmt.Sprintf("%d", now.Add(time.Duration(w.ResetAfterSeconds)*time.Second).Unix())
	}
	return fmt.Sprintf("%.4f", frac), reset
}
