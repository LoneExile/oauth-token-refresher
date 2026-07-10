package oauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"time"
)

// PKCE is an RFC 7636 verifier/challenge pair (S256).
type PKCE struct {
	Verifier  string
	Challenge string
}

// GeneratePKCE mints a PKCE pair matching OMP: verifier = base64url(96 random
// bytes), challenge = base64url(SHA-256(verifier)).
func GeneratePKCE() (PKCE, error) {
	b := make([]byte, 96)
	if _, err := rand.Read(b); err != nil {
		return PKCE{}, err
	}
	verifier := base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(verifier))
	return PKCE{Verifier: verifier, Challenge: base64.RawURLEncoding.EncodeToString(sum[:])}, nil
}

// GenerateState mints an anti-CSRF state token (16 random bytes, hex), matching
// OMP's OAuthCallbackFlow.generateState.
func GenerateState() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// PollStatus is the outcome of a single device-flow poll.
type PollStatus int

const (
	PollPending  PollStatus = iota // authorization_pending — keep polling
	PollSlowDown                   // slow_down — back off, then keep polling
	PollComplete                   // tokens issued
)

// DeviceAuth is the RFC 8628 device authorization response shown to the user.
type DeviceAuth struct {
	DeviceCode              string
	UserCode                string
	VerificationURIComplete string
	Interval                time.Duration
	ExpiresAt               time.Time
}

// DeviceLogin is the OAuth 2.0 Device Authorization Grant (RFC 8628), used by
// providers where the user approves on a separate device (xAI).
type DeviceLogin interface {
	StartDevice(ctx context.Context) (DeviceAuth, error)
	// PollDevice polls once. On PollComplete the Credential is valid; on
	// PollPending/PollSlowDown it is zero and err is nil; a hard failure returns err.
	PollDevice(ctx context.Context, deviceCode string) (Credential, PollStatus, error)
}

// PasteLogin is an authorization-code + PKCE flow completed out-of-band: the
// user authorizes in a browser and pastes the returned code back (Anthropic).
type PasteLogin interface {
	// RedirectURI is the (registered) redirect URI sent in both the authorize
	// request and the code exchange.
	RedirectURI() string
	// AuthURL builds the provider authorization URL for the given PKCE + state.
	AuthURL(pkce PKCE, state string) string
	// ExchangeCode trades an authorization code (+ returned state) for a Credential.
	ExchangeCode(ctx context.Context, code, state string, pkce PKCE) (Credential, error)
}
