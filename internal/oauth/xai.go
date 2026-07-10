package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// XAIClient refreshes xAI SuperGrok OAuth tokens. The token endpoint is
// discovered via OIDC (.well-known/openid-configuration) and the refresh is an
// RFC 6749 form-encoded grant.
type XAIClient struct {
	Issuer   string
	ClientID string
	// Scope is requested during device-authorization login (unused for refresh).
	Scope string
	HTTP  *http.Client
}

// NewXAI builds an xAI refresher for the given OIDC issuer and client ID.
func NewXAI(issuer, clientID string) *XAIClient {
	return &XAIClient{
		Issuer:   strings.TrimRight(issuer, "/"),
		ClientID: clientID,
		Scope:    XAIScope,
		HTTP:     &http.Client{Timeout: 30 * time.Second},
	}
}

type oidcConfig struct {
	TokenEndpoint string `json:"token_endpoint"`
}

func (c *XAIClient) tokenEndpoint(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.Issuer+"/.well-known/openid-configuration", nil)
	if err != nil {
		return "", err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return "", fmt.Errorf("oidc discovery: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("oidc discovery: status %d: %s", resp.StatusCode, truncate(body, 200))
	}
	var cfg oidcConfig
	if err := json.Unmarshal(body, &cfg); err != nil {
		return "", err
	}
	if cfg.TokenEndpoint == "" {
		return "", fmt.Errorf("oidc discovery: empty token_endpoint")
	}
	return cfg.TokenEndpoint, nil
}

// Refresh exchanges refresh_token for a new access token (and optional new refresh).
func (c *XAIClient) Refresh(ctx context.Context, refreshToken string) (Credential, error) {
	ep, err := c.tokenEndpoint(ctx)
	if err != nil {
		return Credential{}, err
	}
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("client_id", c.ClientID)
	form.Set("refresh_token", refreshToken)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ep, strings.NewReader(form.Encode()))
	if err != nil {
		return Credential{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

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

// XAIScope is the OAuth scope OMP requests for xAI Grok device login.
const XAIScope = "openid profile email offline_access grok-cli:access api:access"

// oauthError is the RFC 6749 error body shape (shared by device/paste flows).
type oauthError struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

func (c *XAIClient) deviceEndpoint() string { return c.Issuer + "/oauth2/device/code" }

type xaiDeviceResp struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// StartDevice requests a device code (RFC 8628) from xAI.
func (c *XAIClient) StartDevice(ctx context.Context) (DeviceAuth, error) {
	form := url.Values{}
	form.Set("client_id", c.ClientID)
	form.Set("scope", c.Scope)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.deviceEndpoint(), strings.NewReader(form.Encode()))
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
	var dr xaiDeviceResp
	if err := json.Unmarshal(body, &dr); err != nil {
		return DeviceAuth{}, err
	}
	if dr.DeviceCode == "" || dr.UserCode == "" || dr.ExpiresIn <= 0 {
		return DeviceAuth{}, fmt.Errorf("device-code response missing required fields")
	}
	uri := dr.VerificationURIComplete
	if uri == "" {
		uri = dr.VerificationURI
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
		ExpiresAt:               time.Now().Add(time.Duration(dr.ExpiresIn) * time.Second),
	}, nil
}

// PollDevice polls the token endpoint once for the device-code grant.
func (c *XAIClient) PollDevice(ctx context.Context, deviceCode string) (Credential, PollStatus, error) {
	ep, err := c.tokenEndpoint(ctx)
	if err != nil {
		return Credential{}, PollPending, err
	}
	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
	form.Set("client_id", c.ClientID)
	form.Set("device_code", deviceCode)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ep, strings.NewReader(form.Encode()))
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
		var tr TokenResponse
		if err := json.Unmarshal(body, &tr); err != nil {
			return Credential{}, PollPending, err
		}
		if tr.AccessToken == "" || tr.RefreshToken == "" || tr.ExpiresIn <= 0 {
			return Credential{}, PollPending, fmt.Errorf("device token response missing access/refresh/expires_in")
		}
		return credentialFrom(tr, ""), PollComplete, nil
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
