package oauth

import (
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

// Cline (ClinePass) OAuth constants. ClinePass authenticates via WorkOS User
// Management (RFC 8628 device flow); the resulting access token is a WorkOS JWT
// that api.cline.bot accepts as `Authorization: Bearer workos:<jwt>`. The
// `workos:` prefix is how the gateway tells a WorkOS OAuth token apart from an
// `sk_` API key, so it is prepended to the stored/mirrored access credential.
//
// Verified live 2026-07-20 against a real ClinePass account:
//   - device authorize: POST /user_management/authorize/device (client_id only)
//   - poll + refresh:   POST /user_management/authenticate
//   - the authenticate response carries NO expires_in, so the access-token
//     expiry is read from the JWT `exp` claim (observed 3600s TTL).
//   - refresh tokens ROTATE on every exchange.
const (
	// ClineWorkOSBase is the WorkOS User Management API base.
	ClineWorkOSBase = "https://api.workos.com"
	// ClineClientID is Cline's public WorkOS client ID (from @cline/llms).
	ClineClientID = "client_01K3A541FN8TA3EPPHTD2325AR"
	// ClineBaseURL is the OpenAI-compatible gateway written to KV as base_url.
	ClineBaseURL = "https://api.cline.bot/api/v1"
	// clineWirePrefix is prepended to the JWT for the api.cline.bot Bearer token.
	clineWirePrefix = "workos:"

	clineDeviceAuthorizePath = "/user_management/authorize/device"
	clineAuthenticatePath    = "/user_management/authenticate"
	clineDeviceGrant         = "urn:ietf:params:oauth:grant-type:device_code"
)

// ClineClient refreshes and logs in ClinePass OAuth tokens via WorkOS. It
// implements both DeviceLogin (RFC 8628) and Refresher.
type ClineClient struct {
	WorkOSBase string
	ClientID   string
	HTTP       *http.Client
}

// NewCline builds a Cline refresher. Empty workosBase/clientID fall back to the
// ClinePass defaults.
func NewCline(workosBase, clientID string) *ClineClient {
	if workosBase == "" {
		workosBase = ClineWorkOSBase
	}
	if clientID == "" {
		clientID = ClineClientID
	}
	return &ClineClient{
		WorkOSBase: strings.TrimRight(workosBase, "/"),
		ClientID:   clientID,
		HTTP:       &http.Client{Timeout: 30 * time.Second},
	}
}

// clineTokenResponse is the WorkOS authenticate response (device poll + refresh).
// WorkOS returns no expires_in; the expiry is derived from the JWT.
type clineTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type clineDeviceResp struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

func (c *ClineClient) authenticateURL() string { return c.WorkOSBase + clineAuthenticatePath }
func (c *ClineClient) deviceURL() string       { return c.WorkOSBase + clineDeviceAuthorizePath }

// jwtExpiryMillis parses the `exp` claim (seconds) from a JWT and returns unix
// milliseconds. The token must be a bare (unprefixed) JWT.
func jwtExpiryMillis(jwt string) (int64, error) {
	parts := strings.Split(jwt, ".")
	if len(parts) < 2 {
		return 0, fmt.Errorf("malformed jwt: want 3 segments, got %d", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return 0, fmt.Errorf("jwt payload decode: %w", err)
	}
	var claims struct {
		Exp int64 `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return 0, fmt.Errorf("jwt payload unmarshal: %w", err)
	}
	if claims.Exp <= 0 {
		return 0, fmt.Errorf("jwt missing exp claim")
	}
	return claims.Exp * 1000, nil
}

// credentialFromCline builds a Credential from a WorkOS authenticate response:
// the access token is wire-prefixed (`workos:`), the expiry comes from the JWT
// exp minus clientSkew, and the rotated refresh token is kept (falling back to
// prevRefresh if the response omitted one).
func credentialFromCline(tr clineTokenResponse, prevRefresh string) (Credential, error) {
	if tr.AccessToken == "" {
		return Credential{}, fmt.Errorf("token response missing access_token")
	}
	expMillis, err := jwtExpiryMillis(tr.AccessToken)
	if err != nil {
		return Credential{}, err
	}
	refresh := tr.RefreshToken
	if refresh == "" {
		refresh = prevRefresh
	}
	// Subtract clientSkew so consumers almost never see a near-dead token.
	expMillis -= clientSkew.Milliseconds()
	return Credential{
		Access:  clineWirePrefix + tr.AccessToken,
		Refresh: refresh,
		Expires: FlexInt64(expMillis),
	}, nil
}

// Refresh exchanges refresh_token for a fresh Credential. WorkOS rotates the
// refresh token on every exchange, so the returned Credential carries the new one.
func (c *ClineClient) Refresh(ctx context.Context, refreshToken string) (Credential, error) {
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("client_id", c.ClientID)
	form.Set("refresh_token", refreshToken)

	tr, err := c.postAuthenticate(ctx, form)
	if err != nil {
		return Credential{}, fmt.Errorf("token refresh: %w", err)
	}
	return credentialFromCline(tr, refreshToken)
}

// StartDevice requests a device code (RFC 8628) from WorkOS. Unlike xAI, the
// WorkOS device-authorization request carries only the client_id (no scope).
func (c *ClineClient) StartDevice(ctx context.Context) (DeviceAuth, error) {
	form := url.Values{}
	form.Set("client_id", c.ClientID)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.deviceURL(), strings.NewReader(form.Encode()))
	if err != nil {
		return DeviceAuth{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return DeviceAuth{}, fmt.Errorf("device-code request: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return DeviceAuth{}, fmt.Errorf("device-code request: status %d: %s", resp.StatusCode, truncate(body, 400))
	}
	var dr clineDeviceResp
	if err := json.Unmarshal(body, &dr); err != nil {
		return DeviceAuth{}, err
	}
	if dr.DeviceCode == "" || dr.UserCode == "" || dr.VerificationURI == "" {
		return DeviceAuth{}, fmt.Errorf("device-code response missing required fields")
	}
	uri := dr.VerificationURIComplete
	if uri == "" {
		uri = dr.VerificationURI
	}
	expiresIn := dr.ExpiresIn
	if expiresIn <= 0 {
		expiresIn = 300
	}
	interval := time.Duration(dr.Interval) * time.Second
	if interval < time.Second {
		interval = 5 * time.Second
	}
	return DeviceAuth{
		DeviceCode:              dr.DeviceCode,
		UserCode:                dr.UserCode,
		VerificationURIComplete: uri,
		Interval:                interval,
		ExpiresAt:               time.Now().Add(time.Duration(expiresIn) * time.Second),
	}, nil
}

// PollDevice polls the WorkOS authenticate endpoint once for the device-code grant.
func (c *ClineClient) PollDevice(ctx context.Context, deviceCode string) (Credential, PollStatus, error) {
	form := url.Values{}
	form.Set("grant_type", clineDeviceGrant)
	form.Set("client_id", c.ClientID)
	form.Set("device_code", deviceCode)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.authenticateURL(), strings.NewReader(form.Encode()))
	if err != nil {
		return Credential{}, PollPending, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return Credential{}, PollPending, fmt.Errorf("device poll: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode == http.StatusOK {
		var tr clineTokenResponse
		if err := json.Unmarshal(body, &tr); err != nil {
			return Credential{}, PollPending, err
		}
		if tr.AccessToken == "" || tr.RefreshToken == "" {
			return Credential{}, PollPending, fmt.Errorf("device token response missing access/refresh")
		}
		cred, err := credentialFromCline(tr, "")
		if err != nil {
			return Credential{}, PollPending, err
		}
		return cred, PollComplete, nil
	}
	var oe oauthError
	_ = json.Unmarshal(body, &oe)
	switch oe.Error {
	case "authorization_pending":
		return Credential{}, PollPending, nil
	case "slow_down":
		return Credential{}, PollSlowDown, nil
	}
	msg := oe.ErrorDescription
	if msg == "" {
		msg = oe.Error
	}
	if msg == "" {
		msg = truncate(body, 200)
	}
	return Credential{}, PollPending, fmt.Errorf("device poll failed: %s", msg)
}

// postAuthenticate POSTs a form to the WorkOS authenticate endpoint and decodes
// the token response, surfacing OAuth error bodies on non-200.
func (c *ClineClient) postAuthenticate(ctx context.Context, form url.Values) (clineTokenResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.authenticateURL(), strings.NewReader(form.Encode()))
	if err != nil {
		return clineTokenResponse{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return clineTokenResponse{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return clineTokenResponse{}, fmt.Errorf("status %d: %s", resp.StatusCode, truncate(body, 400))
	}
	var tr clineTokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return clineTokenResponse{}, err
	}
	return tr, nil
}
