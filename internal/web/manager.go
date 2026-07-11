// Package web serves the self-service OAuth login UI and manages the accounts
// behind each provider: a small server-rendered frontend that runs each
// provider's login flow end-to-end and seeds the resulting credential into
// OpenBao, so no manual `bao kv put` is needed.
//
// A provider (e.g. anthropic, xai) can hold MANY accounts at once, each with its
// own OpenBao credential kept fresh by the refresh loop. Exactly one account per
// provider is ACTIVE: its credential is mirrored to the provider's live KV path
// (secret/<provider>/oauth), which is what downstream consumers (ESO → LiteLLM)
// read. Switching accounts copies the chosen account's credential to the live
// path and flips the active pointer — no re-login required.
package web

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/LoneExile/oauth-token-refresher/internal/oauth"
	"github.com/LoneExile/oauth-token-refresher/internal/openbao"
)

// Provider is a login-capable provider wired to its OpenBao KV client. Exactly
// one of Device / Paste is non-nil; Refresher re-mints access tokens in the loop.
type Provider struct {
	Name      string
	Bao       *openbao.Client
	Device    oauth.DeviceLogin
	Paste     oauth.PasteLogin
	Refresher oauth.Refresher
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

	// account being seeded/re-logged by this session
	AccountID    string
	AccountLabel string

	// device flow
	UserCode        string
	VerificationURI string

	// paste flow
	AuthURL string

	// internal (never rendered)
	pkce      oauth.PKCE
	authState string
}

// errNoAccounts / errNoActive mark the two "nothing to serve" refresh outcomes;
// they are recorded like any cycle error but never re-mint a token.
var (
	errNoAccounts = errors.New("no accounts seeded")
	errNoActive   = errors.New("no active account")
)

// Manager tracks active login sessions and manages each provider's accounts.
// Safe for concurrent use. Assumes a single replica (sessions live in memory;
// account state is persisted in OpenBao).
type Manager struct {
	mu        sync.Mutex // guards sessions
	accMu     sync.Mutex // serializes account/registry/live-credential mutations
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

// AccountView is one account row in the dashboard.
type AccountView struct {
	ID         string
	Label      string
	Active     bool
	Seeded     bool
	TokenValid bool
	Expiry     time.Time
	Err        string
}

// ProviderView is the dashboard section for one provider and its accounts.
type ProviderView struct {
	Name     string
	Kind     string
	ActiveID string
	Accounts []AccountView
}

// Providers returns the dashboard sections, reading each account's current
// credential from OpenBao to show whether it is seeded and still valid.
func (m *Manager) Providers() []ProviderView {
	m.accMu.Lock()
	defer m.accMu.Unlock()
	out := make([]ProviderView, 0, len(m.order))
	for _, name := range m.order {
		p := m.providers[name]
		pv := ProviderView{Name: name, Kind: p.Kind()}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		reg, err := m.ensureRegistryLocked(ctx, p)
		if err != nil {
			cancel()
			pv.Accounts = []AccountView{{Err: "registry read error"}}
			out = append(out, pv)
			continue
		}
		pv.ActiveID = reg.Active
		for _, a := range reg.Accounts {
			av := AccountView{ID: a.ID, Label: a.Label, Active: a.ID == reg.Active}
			cred, cerr := p.Bao.ReadCredentialAt(ctx, p.Bao.AccountPath(a.ID))
			switch {
			case cerr != nil:
				if !errors.Is(cerr, openbao.ErrNotFound) {
					av.Err = "read error"
				}
			case cred.Access != "":
				av.Seeded = true
				av.Expiry = time.UnixMilli(cred.Expires.Int64())
				av.TokenValid = cred.Expires.Int64() > 0 && m.clock().Before(av.Expiry)
			}
			pv.Accounts = append(pv.Accounts, av)
		}
		cancel()
		out = append(out, pv)
	}
	return out
}

// StartLogin begins a login for the named provider. accountID == "" adds a NEW
// account (label names it); a non-empty accountID re-logs an existing account.
// Device flows start polling in the background; paste flows return a session
// with the authorization URL.
func (m *Manager) StartLogin(provider, accountID, label string) (*Session, error) {
	p, ok := m.providers[provider]
	if !ok {
		return nil, fmt.Errorf("unknown provider %q", provider)
	}
	id, lbl, err := m.resolveAccount(provider, accountID, label)
	if err != nil {
		return nil, err
	}
	sid, err := oauth.GenerateState()
	if err != nil {
		return nil, err
	}
	sess := &Session{ID: sid, Provider: provider, AccountID: id, AccountLabel: lbl, Kind: p.Kind(), State: StatePending, Created: m.clock()}

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
		return nil, fmt.Errorf("provider %q has no login flow", provider)
	}
	return sess, nil
}

// resolveAccount maps the (accountID, label) request onto a concrete account id
// and label: minting a fresh id for a new account, or validating an existing one
// for a re-login.
func (m *Manager) resolveAccount(provider, accountID, label string) (id, lbl string, err error) {
	label = strings.TrimSpace(label)
	if accountID != "" {
		m.accMu.Lock()
		defer m.accMu.Unlock()
		p := m.providers[provider]
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		reg, _ := p.Bao.ReadRegistry(ctx)
		if !reg.Has(accountID) {
			return "", "", fmt.Errorf("unknown account %q", accountID)
		}
		lbl = reg.Label(accountID)
		if label != "" {
			lbl = label
		}
		return accountID, lbl, nil
	}
	nid, err := oauth.GenerateState()
	if err != nil {
		return "", "", err
	}
	if label == "" {
		label = "account-" + nid[:6]
	}
	return nid, label, nil
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
	if err := m.commitLogin(p, id, cred); err != nil {
		m.finish(id, StateError, "authorized but OpenBao write failed: "+err.Error())
		return err
	}
	m.finish(id, StateAuthorized, "")
	return nil
}

// Activate makes account id the provider's active account: its credential is
// copied to the live path and the registry pointer is flipped. No re-login.
func (m *Manager) Activate(provider, id string) error {
	p, ok := m.providers[provider]
	if !ok {
		return fmt.Errorf("unknown provider %q", provider)
	}
	m.accMu.Lock()
	defer m.accMu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	reg, err := m.ensureRegistryLocked(ctx, p)
	if err != nil {
		return err
	}
	if !reg.Has(id) {
		return fmt.Errorf("unknown account %q", id)
	}
	cred, err := p.Bao.ReadCredentialAt(ctx, p.Bao.AccountPath(id))
	if err != nil {
		return err
	}
	if err := p.Bao.WriteCredential(ctx, cred); err != nil {
		return err
	}
	reg.Active = id
	if err := p.Bao.WriteRegistry(ctx, reg); err != nil {
		return err
	}
	slog.Info("active account switched", "provider", provider, "account", id)
	return nil
}

// RemoveAccount deletes account id from OpenBao and the registry. Removing the
// active account promotes the first remaining account (and mirrors it to live).
func (m *Manager) RemoveAccount(provider, id string) error {
	p, ok := m.providers[provider]
	if !ok {
		return fmt.Errorf("unknown provider %q", provider)
	}
	m.accMu.Lock()
	defer m.accMu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	reg, err := m.ensureRegistryLocked(ctx, p)
	if err != nil {
		return err
	}
	if !reg.Has(id) {
		return fmt.Errorf("unknown account %q", id)
	}
	if err := p.Bao.DeleteAt(ctx, p.Bao.AccountPath(id)); err != nil {
		return err
	}
	reg.Remove(id)
	if reg.Active == id {
		reg.Active = ""
		if len(reg.Accounts) > 0 {
			reg.Active = reg.Accounts[0].ID
			if cred, rerr := p.Bao.ReadCredentialAt(ctx, p.Bao.AccountPath(reg.Active)); rerr == nil {
				_ = p.Bao.WriteCredential(ctx, cred)
			}
		}
	}
	if err := p.Bao.WriteRegistry(ctx, reg); err != nil {
		return err
	}
	slog.Info("account removed", "provider", provider, "account", id, "new_active", reg.Active)
	return nil
}

// RefreshResult is one provider's active-account state after a refresh cycle.
type RefreshResult struct {
	Provider  string
	Expiry    time.Time // active account's access expiry (zero if none)
	Refreshed bool      // the active account was re-minted this cycle
	Err       error     // active-account error, or errNoAccounts/errNoActive
}

// RefreshAll runs one refresh cycle across every provider and account, keeping
// each account's credential fresh and mirroring the active account to the live
// path when it is re-minted. Returns per-provider active-account results.
func (m *Manager) RefreshAll(ctx context.Context, skew time.Duration) []RefreshResult {
	m.accMu.Lock()
	defer m.accMu.Unlock()
	out := make([]RefreshResult, 0, len(m.order))
	for _, name := range m.order {
		out = append(out, m.refreshProviderLocked(ctx, m.providers[name], skew))
	}
	return out
}

func (m *Manager) refreshProviderLocked(ctx context.Context, p Provider, skew time.Duration) RefreshResult {
	res := RefreshResult{Provider: p.Name}
	reg, err := m.ensureRegistryLocked(ctx, p)
	if err != nil {
		res.Err = err
		return res
	}
	if len(reg.Accounts) == 0 {
		res.Err = errNoAccounts
		return res
	}

	var (
		activeCred      oauth.Credential
		activeRefreshed bool
		activeErr       error
		activeSeen      bool
	)
	for _, a := range reg.Accounts {
		isActive := a.ID == reg.Active
		cred, refreshed, err := m.refreshAccountLocked(ctx, p, a.ID, skew)
		if err != nil {
			if isActive {
				activeErr, activeSeen = err, true
			} else {
				slog.Warn("inactive account refresh failed", "provider", p.Name, "account", a.ID, "err", err)
			}
			continue
		}
		if isActive {
			activeCred, activeRefreshed, activeSeen = cred, refreshed, true
		}
	}

	if reg.Active == "" || !activeSeen {
		res.Err = errNoActive
		return res
	}
	if activeErr != nil {
		res.Err = activeErr
		return res
	}
	if activeRefreshed {
		if err := p.Bao.WriteCredential(ctx, activeCred); err != nil {
			res.Err = err
			return res
		}
		slog.Info("live credential updated from active account", "provider", p.Name, "account", reg.Active, "expires_ms", activeCred.Expires.Int64())
	}
	res.Expiry = time.UnixMilli(activeCred.Expires.Int64())
	res.Refreshed = activeRefreshed
	return res
}

// refreshAccountLocked reads one account, re-mints it if near expiry, and writes
// the refreshed credential back to its account path.
func (m *Manager) refreshAccountLocked(ctx context.Context, p Provider, id string, skew time.Duration) (oauth.Credential, bool, error) {
	cred, err := p.Bao.ReadCredentialAt(ctx, p.Bao.AccountPath(id))
	if err != nil {
		return oauth.Credential{}, false, err
	}
	if !oauth.NeedsRefresh(cred, skew) {
		return cred, false, nil
	}
	if p.Refresher == nil {
		return cred, false, fmt.Errorf("provider %q has no refresher", p.Name)
	}
	next, err := p.Refresher.Refresh(ctx, cred.Refresh)
	if err != nil {
		return oauth.Credential{}, false, err
	}
	if err := p.Bao.WriteCredentialAt(ctx, p.Bao.AccountPath(id), next); err != nil {
		return oauth.Credential{}, false, err
	}
	return next, true, nil
}

// commitLogin persists a freshly-minted credential for the session's account.
func (m *Manager) commitLogin(p Provider, sessID string, cred oauth.Credential) error {
	m.mu.Lock()
	s := m.sessions[sessID]
	m.mu.Unlock()
	if s == nil {
		return fmt.Errorf("login session gone")
	}
	m.accMu.Lock()
	defer m.accMu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return m.storeAccountLocked(ctx, p, s.AccountID, s.AccountLabel, cred)
}

// storeAccountLocked writes an account's credential, upserts the registry entry,
// and (when the account is or becomes active) mirrors it to the live path.
func (m *Manager) storeAccountLocked(ctx context.Context, p Provider, id, label string, cred oauth.Credential) error {
	reg, err := m.ensureRegistryLocked(ctx, p)
	if err != nil {
		return err
	}
	if err := p.Bao.WriteCredentialAt(ctx, p.Bao.AccountPath(id), cred); err != nil {
		return err
	}
	reg.Upsert(openbao.Account{ID: id, Label: label, CreatedMS: m.clock().UnixMilli()})
	if reg.Active == "" {
		reg.Active = id
	}
	if err := p.Bao.WriteRegistry(ctx, reg); err != nil {
		return err
	}
	if reg.Active == id {
		if err := p.Bao.WriteCredential(ctx, cred); err != nil {
			return err
		}
	}
	return nil
}

// ensureRegistryLocked loads the registry, lazily adopting a pre-existing live
// credential as a "default" account (backward compatibility with the old
// single-credential layout). Caller must hold accMu.
func (m *Manager) ensureRegistryLocked(ctx context.Context, p Provider) (openbao.Registry, error) {
	reg, err := p.Bao.ReadRegistry(ctx)
	if err != nil {
		return openbao.Registry{}, err
	}
	if len(reg.Accounts) > 0 {
		return reg, nil
	}
	live, err := p.Bao.ReadCredential(ctx)
	if err != nil {
		if errors.Is(err, openbao.ErrNotFound) {
			return openbao.Registry{}, nil // nothing seeded yet
		}
		return openbao.Registry{}, err
	}
	if live.Access == "" && live.Refresh == "" {
		return openbao.Registry{}, nil
	}
	const id = "default"
	if err := p.Bao.WriteCredentialAt(ctx, p.Bao.AccountPath(id), live); err != nil {
		return openbao.Registry{}, err
	}
	reg = openbao.Registry{Active: id, Accounts: []openbao.Account{{ID: id, Label: "default", CreatedMS: m.clock().UnixMilli()}}}
	if err := p.Bao.WriteRegistry(ctx, reg); err != nil {
		return openbao.Registry{}, err
	}
	slog.Info("migrated legacy credential to default account", "provider", p.Name)
	return reg, nil
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
			if werr := m.commitLogin(p, id, cred); werr != nil {
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
