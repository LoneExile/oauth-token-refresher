package web

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/LoneExile/oauth-token-refresher/internal/oauth"
	"github.com/LoneExile/oauth-token-refresher/internal/openbao"
)

// fakeVault is a minimal in-memory KV v2 backend: GET/POST on /v1/<m>/data/<p>
// and DELETE on /v1/<m>/metadata/<p>. It lets tests drive the real openbao
// client through the full add / switch / remove / refresh lifecycle.
type fakeVault struct {
	url  string
	mu   sync.Mutex
	data map[string]map[string]any // logical "mount/rest" -> stored data map
}

func newFakeVault(t *testing.T) *fakeVault {
	t.Helper()
	v := &fakeVault{data: map[string]map[string]any{}}
	srv := httptest.NewServer(http.HandlerFunc(v.handle))
	t.Cleanup(srv.Close)
	v.url = srv.URL
	return v
}

func (v *fakeVault) handle(w http.ResponseWriter, r *http.Request) {
	parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/v1/"), "/", 3)
	if len(parts) < 3 {
		http.Error(w, "bad path", http.StatusBadRequest)
		return
	}
	mount, kind, rest := parts[0], parts[1], parts[2]
	logical := mount + "/" + rest
	v.mu.Lock()
	defer v.mu.Unlock()
	switch {
	case r.Method == http.MethodGet && kind == "data":
		d, ok := v.data[logical]
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"data": d}})
	case r.Method == http.MethodPost && kind == "data":
		var body struct {
			Data map[string]any `json:"data"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		v.data[logical] = body.Data
		w.WriteHeader(http.StatusNoContent)
	case r.Method == http.MethodDelete && kind == "metadata":
		delete(v.data, logical)
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "unsupported", http.StatusMethodNotAllowed)
	}
}

func (v *fakeVault) client(kvPath, baseURL string) *openbao.Client {
	return openbao.New(v.url, "tok", kvPath, baseURL)
}

func (v *fakeVault) get(logical string, out any) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	d, ok := v.data[logical]
	if !ok {
		return false
	}
	b, _ := json.Marshal(d)
	_ = json.Unmarshal(b, out)
	return true
}

func (v *fakeVault) cred(logical string) (oauth.Credential, bool) {
	var c oauth.Credential
	ok := v.get(logical, &c)
	return c, ok
}

func (v *fakeVault) registry(logical string) (openbao.Registry, bool) {
	var reg openbao.Registry
	ok := v.get(logical, &reg)
	return reg, ok
}

func (v *fakeVault) seedCred(logical string, c oauth.Credential) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.data[logical] = map[string]any{"access": c.Access, "refresh": c.Refresh, "expires": c.Expires.Int64()}
}

func (v *fakeVault) seedRegistry(logical string, reg openbao.Registry) {
	v.mu.Lock()
	defer v.mu.Unlock()
	b, _ := json.Marshal(reg)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	v.data[logical] = m
}

type fakeDevice struct {
	interval   time.Duration
	polls      int
	completeAt int
	cred       oauth.Credential
	failErr    error
}

func (f *fakeDevice) StartDevice(context.Context) (oauth.DeviceAuth, error) {
	return oauth.DeviceAuth{DeviceCode: "dc", UserCode: "UC-1", VerificationURIComplete: "https://verify", Interval: f.interval, ExpiresAt: time.Now().Add(time.Minute)}, nil
}

func (f *fakeDevice) PollDevice(context.Context, string) (oauth.Credential, oauth.PollStatus, error) {
	f.polls++
	if f.failErr != nil {
		return oauth.Credential{}, oauth.PollPending, f.failErr
	}
	if f.polls >= f.completeAt {
		return f.cred, oauth.PollComplete, nil
	}
	return oauth.Credential{}, oauth.PollPending, nil
}

type fakePaste struct {
	cred                          oauth.Credential
	err                           error
	gotCode, gotState, gotVerifer string
}

func (f *fakePaste) RedirectURI() string { return "http://localhost:54545/callback" }
func (f *fakePaste) AuthURL(p oauth.PKCE, state string) string {
	return "https://authorize?state=" + state + "&cc=" + p.Challenge
}
func (f *fakePaste) ExchangeCode(_ context.Context, code, state string, p oauth.PKCE) (oauth.Credential, error) {
	f.gotCode, f.gotState, f.gotVerifer = code, state, p.Verifier
	if f.err != nil {
		return oauth.Credential{}, f.err
	}
	return f.cred, nil
}

// fakeRefresher re-mints a fixed credential and counts calls.
type fakeRefresher struct {
	mu   sync.Mutex
	out  oauth.Credential
	call int
}

func (f *fakeRefresher) Refresh(context.Context, string) (oauth.Credential, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.call++
	return f.out, nil
}

func (f *fakeRefresher) calls() int { f.mu.Lock(); defer f.mu.Unlock(); return f.call }

func waitState(t *testing.T, m *Manager, id string, want SessionState) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if s, ok := m.Session(id); ok && s.State == want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	s, _ := m.Session(id)
	t.Fatalf("timeout waiting for %s; got %s (%s)", want, s.State, s.Message)
}

func validCred(access string) oauth.Credential {
	return oauth.Credential{Access: access, Refresh: "R", Expires: oauth.FlexInt64(time.Now().Add(time.Hour).UnixMilli())}
}

func TestPasteLoginSeedsFirstAccountActive(t *testing.T) {
	v := newFakeVault(t)
	bao := v.client("secret/anthropic/oauth", "https://base")
	fp := &fakePaste{cred: validCred("AT")}
	m := NewManager([]Provider{{Name: "anthropic", Bao: bao, Paste: fp}})

	sess, err := m.StartLogin("anthropic", "", "alice")
	if err != nil {
		t.Fatal(err)
	}
	if sess.Kind != "paste" || sess.AuthURL == "" || sess.State != StatePending || sess.AccountLabel != "alice" {
		t.Fatalf("sess=%#v", sess)
	}
	if err := m.SubmitCode(sess.ID, "  CODE#ST  "); err != nil {
		t.Fatal(err)
	}
	snap, _ := m.Session(sess.ID)
	if snap.State != StateAuthorized {
		t.Fatalf("state=%s msg=%s", snap.State, snap.Message)
	}
	if fp.gotCode != "CODE#ST" {
		t.Errorf("exchange code=%q (manager should trim)", fp.gotCode)
	}
	if fp.gotState != snap.authState || fp.gotVerifer != snap.pkce.Verifier {
		t.Errorf("exchange got state/verifier not from session")
	}
	// First account → active → mirrored to the live path AND its own path.
	if c, ok := v.cred("secret/anthropic/oauth"); !ok || c.Access != "AT" {
		t.Fatalf("live=%#v ok=%v", c, ok)
	}
	if c, ok := v.cred("secret/anthropic/accounts/" + snap.AccountID); !ok || c.Access != "AT" {
		t.Fatalf("account=%#v ok=%v", c, ok)
	}
	reg, ok := v.registry("secret/anthropic/registry")
	if !ok || reg.Active != snap.AccountID || len(reg.Accounts) != 1 || reg.Accounts[0].Label != "alice" {
		t.Fatalf("registry=%#v ok=%v", reg, ok)
	}
}

func TestPasteLoginExchangeErrorLeavesLiveUntouched(t *testing.T) {
	v := newFakeVault(t)
	bao := v.client("secret/anthropic/oauth", "https://base")
	fp := &fakePaste{err: errors.New("bad code")}
	m := NewManager([]Provider{{Name: "anthropic", Bao: bao, Paste: fp}})
	sess, _ := m.StartLogin("anthropic", "", "alice")
	if err := m.SubmitCode(sess.ID, "x"); err == nil {
		t.Fatal("expected exchange error")
	}
	snap, _ := m.Session(sess.ID)
	if snap.State != StateError {
		t.Errorf("state=%s", snap.State)
	}
	if _, ok := v.cred("secret/anthropic/oauth"); ok {
		t.Error("must not write live credential on exchange failure")
	}
}

func TestDeviceLoginFlow(t *testing.T) {
	v := newFakeVault(t)
	bao := v.client("secret/xai/oauth", "https://base")
	fd := &fakeDevice{interval: time.Millisecond, completeAt: 2, cred: validCred("DAT")}
	m := NewManager([]Provider{{Name: "xai", Bao: bao, Device: fd}})
	m.sleep = func(time.Duration) {} // no real backoff in tests

	sess, err := m.StartLogin("xai", "", "grok")
	if err != nil {
		t.Fatal(err)
	}
	if sess.Kind != "device" || sess.UserCode != "UC-1" || sess.VerificationURI == "" {
		t.Fatalf("sess=%#v", sess)
	}
	waitState(t, m, sess.ID, StateAuthorized)
	if c, ok := v.cred("secret/xai/oauth"); !ok || c.Access != "DAT" {
		t.Fatalf("live=%#v ok=%v", c, ok)
	}
}

func TestDeviceLoginError(t *testing.T) {
	v := newFakeVault(t)
	bao := v.client("secret/xai/oauth", "https://base")
	fd := &fakeDevice{interval: time.Millisecond, failErr: errors.New("device fail")}
	m := NewManager([]Provider{{Name: "xai", Bao: bao, Device: fd}})
	m.sleep = func(time.Duration) {}
	sess, _ := m.StartLogin("xai", "", "grok")
	waitState(t, m, sess.ID, StateError)
}

func TestStartLoginUnknown(t *testing.T) {
	m := NewManager(nil)
	if _, err := m.StartLogin("nope", "", ""); err == nil {
		t.Fatal("expected error for unknown provider")
	}
}

func TestReloginUnknownAccount(t *testing.T) {
	v := newFakeVault(t)
	bao := v.client("secret/anthropic/oauth", "https://base")
	m := NewManager([]Provider{{Name: "anthropic", Bao: bao, Paste: &fakePaste{}}})
	if _, err := m.StartLogin("anthropic", "ghost", ""); err == nil {
		t.Fatal("re-login of an unknown account must error")
	}
}

// addAccount runs a paste login for label and returns the new account id.
func addAccount(t *testing.T, m *Manager, fp *fakePaste, provider, label, access string) string {
	t.Helper()
	fp.cred = validCred(access)
	s, err := m.StartLogin(provider, "", label)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.SubmitCode(s.ID, "code"); err != nil {
		t.Fatal(err)
	}
	snap, _ := m.Session(s.ID)
	return snap.AccountID
}

func TestMultiAccountAddAndSwitch(t *testing.T) {
	v := newFakeVault(t)
	bao := v.client("secret/anthropic/oauth", "https://base")
	fp := &fakePaste{}
	m := NewManager([]Provider{{Name: "anthropic", Bao: bao, Paste: fp}})

	alice := addAccount(t, m, fp, "anthropic", "alice", "ALICE")
	bob := addAccount(t, m, fp, "anthropic", "bob", "BOB")

	// First-added account stays active until an explicit switch.
	if c, _ := v.cred("secret/anthropic/oauth"); c.Access != "ALICE" {
		t.Fatalf("live should be ALICE, got %q", c.Access)
	}
	reg, _ := v.registry("secret/anthropic/registry")
	if reg.Active != alice || len(reg.Accounts) != 2 {
		t.Fatalf("registry=%#v", reg)
	}

	// Switch to bob — live path follows, both account paths retained.
	if err := m.Activate("anthropic", bob); err != nil {
		t.Fatal(err)
	}
	if c, _ := v.cred("secret/anthropic/oauth"); c.Access != "BOB" {
		t.Fatalf("live should be BOB after switch, got %q", c.Access)
	}
	if reg, _ := v.registry("secret/anthropic/registry"); reg.Active != bob {
		t.Fatalf("active should be bob, got %q", reg.Active)
	}
	if c, _ := v.cred("secret/anthropic/accounts/" + alice); c.Access != "ALICE" {
		t.Errorf("alice account clobbered: %q", c.Access)
	}
	if c, _ := v.cred("secret/anthropic/accounts/" + bob); c.Access != "BOB" {
		t.Errorf("bob account wrong: %q", c.Access)
	}

	// Dashboard reflects both, bob marked active.
	views := m.Providers()
	if len(views) != 1 || len(views[0].Accounts) != 2 || views[0].ActiveID != bob {
		t.Fatalf("views=%#v", views)
	}
	for _, a := range views[0].Accounts {
		if !a.Seeded || !a.TokenValid {
			t.Errorf("account %s not seeded/valid: %#v", a.ID, a)
		}
	}
}

func TestRemoveActiveAccountPromotes(t *testing.T) {
	v := newFakeVault(t)
	bao := v.client("secret/anthropic/oauth", "https://base")
	fp := &fakePaste{}
	m := NewManager([]Provider{{Name: "anthropic", Bao: bao, Paste: fp}})

	alice := addAccount(t, m, fp, "anthropic", "alice", "ALICE") // active
	bob := addAccount(t, m, fp, "anthropic", "bob", "BOB")

	if err := m.RemoveAccount("anthropic", alice); err != nil {
		t.Fatal(err)
	}
	reg, _ := v.registry("secret/anthropic/registry")
	if reg.Has(alice) || reg.Active != bob || len(reg.Accounts) != 1 {
		t.Fatalf("registry after remove=%#v", reg)
	}
	if _, ok := v.cred("secret/anthropic/accounts/" + alice); ok {
		t.Error("alice account credential should be deleted")
	}
	if c, _ := v.cred("secret/anthropic/oauth"); c.Access != "BOB" {
		t.Fatalf("live should be promoted to BOB, got %q", c.Access)
	}
}

func TestRefreshAllRefreshesEveryAccountAndMirrorsActive(t *testing.T) {
	v := newFakeVault(t)
	bao := v.client("secret/anthropic/oauth", "https://base")
	fr := &fakeRefresher{out: validCred("FRESH")}
	m := NewManager([]Provider{{Name: "anthropic", Bao: bao, Paste: &fakePaste{}, Refresher: fr}})

	// Two seeded accounts whose access tokens are already expired (refresh due).
	expired := oauth.Credential{Access: "OLD", Refresh: "R", Expires: oauth.FlexInt64(time.Now().Add(-time.Hour).UnixMilli())}
	v.seedCred("secret/anthropic/accounts/a1", expired)
	v.seedCred("secret/anthropic/accounts/a2", expired)
	v.seedRegistry("secret/anthropic/registry", openbao.Registry{
		Active:   "a1",
		Accounts: []openbao.Account{{ID: "a1", Label: "one"}, {ID: "a2", Label: "two"}},
	})

	res := m.RefreshAll(context.Background(), time.Minute)
	if fr.calls() != 2 {
		t.Fatalf("expected both accounts refreshed, calls=%d", fr.calls())
	}
	for _, id := range []string{"a1", "a2"} {
		if c, _ := v.cred("secret/anthropic/accounts/" + id); c.Access != "FRESH" {
			t.Errorf("account %s not refreshed: %q", id, c.Access)
		}
	}
	if c, _ := v.cred("secret/anthropic/oauth"); c.Access != "FRESH" {
		t.Fatalf("active account not mirrored to live: %q", c.Access)
	}
	if len(res) != 1 || res[0].Err != nil || !res[0].Refreshed {
		t.Fatalf("result=%#v", res)
	}
}

func TestRefreshAllUnseededReportsNoAccounts(t *testing.T) {
	v := newFakeVault(t)
	bao := v.client("secret/anthropic/oauth", "https://base")
	m := NewManager([]Provider{{Name: "anthropic", Bao: bao, Paste: &fakePaste{}, Refresher: &fakeRefresher{}}})
	res := m.RefreshAll(context.Background(), time.Minute)
	if len(res) != 1 || !errors.Is(res[0].Err, errNoAccounts) {
		t.Fatalf("expected errNoAccounts, got %#v", res)
	}
}

func TestLegacyCredentialMigratesToDefaultAccount(t *testing.T) {
	v := newFakeVault(t)
	// A pre-existing single credential at the live path (old layout), no registry.
	v.seedCred("secret/xai/oauth", validCred("LEGACY"))
	bao := v.client("secret/xai/oauth", "https://base")
	m := NewManager([]Provider{{Name: "xai", Bao: bao, Device: &fakeDevice{}}})

	views := m.Providers()
	if len(views) != 1 || len(views[0].Accounts) != 1 {
		t.Fatalf("views=%#v", views)
	}
	a := views[0].Accounts[0]
	if a.Label != "default" || !a.Active || !a.Seeded || !a.TokenValid {
		t.Fatalf("migrated account=%#v", a)
	}
	if c, ok := v.cred("secret/xai/accounts/default"); !ok || c.Access != "LEGACY" {
		t.Fatalf("legacy cred not copied to default account: %#v ok=%v", c, ok)
	}
	if reg, _ := v.registry("secret/xai/registry"); reg.Active != "default" {
		t.Fatalf("registry active=%q", reg.Active)
	}
}
