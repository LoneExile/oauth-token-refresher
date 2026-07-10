// Package oauth refreshes provider OAuth access tokens using their stored
// refresh token. Each provider implements Refresher; the credential shape and
// the 5-minute client skew match OMP's agent.db convention so tokens minted by
// `omp /login <provider>` and re-minted here are interchangeable.
package oauth

import (
	"bytes"
	"context"
	"encoding/json"
	"strconv"
	"time"
)

// Credential is the OAuth pair stored in OpenBao (matches OMP agent.db shape).
type Credential struct {
	Access  string `json:"access"`
	Refresh string `json:"refresh"`
	// Expires is unix milliseconds (OMP convention). OpenBao KV may return it
	// as a JSON number or as a string (bao kv put without typing).
	Expires FlexInt64 `json:"expires"`
}

// FlexInt64 unmarshals JSON numbers or numeric strings into int64.
type FlexInt64 int64

func (f *FlexInt64) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || string(b) == "null" {
		*f = 0
		return nil
	}
	if b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		if s == "" {
			*f = 0
			return nil
		}
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return err
		}
		*f = FlexInt64(n)
		return nil
	}
	var n int64
	if err := json.Unmarshal(b, &n); err != nil {
		return err
	}
	*f = FlexInt64(n)
	return nil
}

func (f FlexInt64) MarshalJSON() ([]byte, error) {
	return json.Marshal(int64(f))
}

func (f FlexInt64) Int64() int64 { return int64(f) }

// TokenResponse is the OAuth token endpoint response shared by all providers.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
}

// clientSkew is subtracted from the real expiry so consumers almost never see a
// near-dead token. Matches OMP's ACCESS_TOKEN_CLIENT_SKEW (5 minutes).
const clientSkew = 5 * time.Minute

// credentialFrom builds a Credential from a token response, keeping the previous
// refresh token when the provider does not rotate it.
func credentialFrom(tr TokenResponse, prevRefresh string) Credential {
	refresh := tr.RefreshToken
	if refresh == "" {
		refresh = prevRefresh
	}
	expiresAt := time.Now().Add(time.Duration(tr.ExpiresIn)*time.Second - clientSkew)
	return Credential{
		Access:  tr.AccessToken,
		Refresh: refresh,
		Expires: FlexInt64(expiresAt.UnixMilli()),
	}
}

// Refresher exchanges a refresh token for a fresh Credential.
type Refresher interface {
	// Refresh returns a new Credential; the previous refresh token is passed so
	// implementations can carry it forward when the endpoint omits a new one.
	Refresh(ctx context.Context, refreshToken string) (Credential, error)
}

// NeedsRefresh reports whether access should be re-minted given skew.
func NeedsRefresh(cred Credential, skew time.Duration) bool {
	if cred.Refresh == "" {
		return false
	}
	if cred.Access == "" || cred.Expires.Int64() == 0 {
		return true
	}
	return time.Now().Add(skew).UnixMilli() >= cred.Expires.Int64()
}

func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "…"
}
