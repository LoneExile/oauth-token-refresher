// Package web serves the self-service OAuth login UI: a small server-rendered
// frontend that runs each provider's login flow end-to-end and seeds the
// resulting credential into OpenBao, so no manual `bao kv put` is needed.
package web

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/LoneExile/oauth-token-refresher/internal/oauth"
	"github.com/LoneExile/oauth-token-refresher/internal/openbao"
)

// Provider is a login-capable provider wired to its OpenBao KV client. Exactly
// one of Device / Paste is non-nil.
type Provider struct {
	Name   string
	Bao    *openbao.Client
	Device oauth.DeviceLogin
	Paste  oauth.PasteLogin
}

// Kind reports the login flow: "device" (RFC 8628) or "paste" (auth-code+PKCE).
func (p Provider) Kind() string {
	if p.Device != nil {
		return "device"
	}
	return "paste"
}

// SessionState is the lifecycle of a single login attempt.
type SessionState string

const (
	StatePending    SessionState = "pending"
	StateAuthorized SessionState = "authorized"
	StateError      SessionState = "error"
	StateExpired    SessionState = "expired"
)

// Session is one in-progress or finished login.
type Session struct {
	ID       string
	Provider string
	Kind     string
	State    SessionState
	Message  string
	Created  time.Time
	Expires  time.Time

	// device flow
	UserCode        string
	VerificationURI string

	// paste flow
	AuthURL string

	// internal (never rendered)
	pkce      oauth.PKCE
	authState string
}

// Manager tracks active login sessions and drives each provider's flow. Safe
// for concurrent use. Assumes a single replica (sessions live in memory).
type Manager struct {
	mu        sync.Mutex
	sessions  map[string]*Session
	providers map[string]Provider
	order     []string
	ttl       time.Duration

	// injectable for tests
	clock func() time.Time
	sleep func(time.Duration)
}

// NewManager builds a Manager for the given providers (dashboard order preserved).
func NewManager(providers []Provider) *Manager {
	m := &Manager{
		sessions:  make(map[string]*Session),
		providers: make(map[string]Provider, len(providers)),
		ttl:       15 * time.Minute,
		clock:     time.Now,
		sleep:     time.Sleep,
	}
	for _, p := range providers {
		if _, ok := m.providers[p.Name]; ok {
			continue
		}
		m.providers[p.Name] = p
		m.order = append(m.order, p.Name)
	}
	return m
}

// ProviderView is the dashboard row for one provider.
type ProviderView struct {
	Name       string
	Kind       string
	Seeded     bool
	TokenValid bool
	Expiry     time.Time
	Err        string
}

// Providers returns the dashboard rows, reading each provider's current
// credential from OpenBao to show whether it is seeded and still valid.
func (m *Manager) Providers() []ProviderView {
	out := make([]ProviderView, 0, len(m.order))
	for _, name := range m.order {
		p := m.providers[name]
		pv := ProviderView{Name: name, Kind: p.Kind()}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		cred, err := p.Bao.ReadCredential(ctx)
		cancel()
		switch {
		case err != nil:
			if !strings.Contains(err.Error(), "not found") {
				pv.Err = "read error"
			}
		case cred.Access != "":
			pv.Seeded = true
			pv.Expiry = time.UnixMilli(cred.Expires.Int64())
			pv.TokenValid = cred.Expires.Int64() > 0 && m.clock().Before(pv.Expiry)
		}
		out = append(out, pv)
	}
	return out
}

// StartLogin begins a login for the named provider. Device flows start polling
// in the background; paste flows return a session with the authorization URL.
func (m *Manager) StartLogin(name string) (*Session, error) {
	p, ok := m.providers[name]
	if !ok {
		return nil, fmt.Errorf("unknown provider %q", name)
	}
	id, err := oauth.GenerateState()
	if err != nil {
		return nil, err
	}
	sess := &Session{ID: id, Provider: name, Kind: p.Kind(), State: StatePending, Created: m.clock()}

	switch {
	case p.Device != nil:
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		da, err := p.Device.StartDevice(ctx)
		cancel()
		if err != nil {
			return nil, err
		}
		sess.UserCode = da.UserCode
		sess.VerificationURI = da.VerificationURIComplete
		sess.Expires = da.ExpiresAt
		m.put(sess)
		go m.pollDevice(p, sess.ID, da)
	case p.Paste != nil:
		pkce, err := oauth.GeneratePKCE()
		if err != nil {
			return nil, err
		}
		st, err := oauth.GenerateState()
		if err != nil {
			return nil, err
		}
		sess.pkce = pkce
		sess.authState = st
		sess.AuthURL = p.Paste.AuthURL(pkce, st)
		sess.Expires = m.clock().Add(m.ttl)
		m.put(sess)
	default:
		return nil, fmt.Errorf("provider %q has no login flow", name)
	}
	return sess, nil
}

// SubmitCode completes a paste-flow login with the pasted authorization code.
func (m *Manager) SubmitCode(id, code string) error {
	m.mu.Lock()
	sess := m.sessions[id]
	m.mu.Unlock()
	if sess == nil {
		return fmt.Errorf("unknown or expired login session")
	}
	if sess.Kind != "paste" {
		return fmt.Errorf("session is not a paste-code flow")
	}
	p := m.providers[sess.Provider]
	if p.Paste == nil {
		return fmt.Errorf("provider %q has no paste flow", sess.Provider)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cred, err := p.Paste.ExchangeCode(ctx, strings.TrimSpace(code), sess.authState, sess.pkce)
	if err != nil {
		m.finish(id, StateError, err.Error())
		return err
	}
	if err := m.write(p, cred); err != nil {
		m.finish(id, StateError, "authorized but OpenBao write failed: "+err.Error())
		return err
	}
	m.finish(id, StateAuthorized, "")
	return nil
}

// Session returns a snapshot copy of the session, if present.
func (m *Manager) Session(id string) (Session, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.sessions[id]
	if s == nil {
		return Session{}, false
	}
	return *s, true
}

// pollDevice runs the RFC 8628 poll loop until authorized, failed, or expired.
func (m *Manager) pollDevice(p Provider, id string, da oauth.DeviceAuth) {
	interval := da.Interval
	if interval < time.Second {
		interval = 5 * time.Second
	}
	for {
		if m.clock().After(da.ExpiresAt) {
			m.finish(id, StateExpired, "device code expired before authorization")
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		cred, status, err := p.Device.PollDevice(ctx, da.DeviceCode)
		cancel()
		switch {
		case err != nil:
			m.finish(id, StateError, err.Error())
			return
		case status == oauth.PollComplete:
			if werr := m.write(p, cred); werr != nil {
				m.finish(id, StateError, "authorized but OpenBao write failed: "+werr.Error())
				return
			}
			m.finish(id, StateAuthorized, "")
			return
		case status == oauth.PollSlowDown:
			interval += 5 * time.Second
		}
		m.sleep(interval)
	}
}

func (m *Manager) write(p Provider, cred oauth.Credential) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return p.Bao.WriteCredential(ctx, cred)
}

func (m *Manager) put(s *Session) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cutoff := m.clock().Add(-m.ttl)
	for k, v := range m.sessions {
		if v.Created.Before(cutoff) {
			delete(m.sessions, k)
		}
	}
	m.sessions[s.ID] = s
}

func (m *Manager) finish(id string, state SessionState, msg string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s := m.sessions[id]; s != nil {
		s.State = state
		s.Message = msg
	}
}
