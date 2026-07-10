package web

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/LoneExile/oauth-token-refresher/internal/oauth"
	"github.com/LoneExile/oauth-token-refresher/internal/openbao"
)

// newMockBao returns a KV client whose POSTs are captured; GET 404s (unseeded).
func newMockBao(t *testing.T) (*openbao.Client, func() *oauth.Credential) {
	t.Helper()
	var mu sync.Mutex
	var written *oauth.Credential
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			http.Error(w, "secret not found", http.StatusNotFound)
			return
		}
		var payload struct {
			Data oauth.Credential `json:"data"`
		}
		_ = json.NewDecoder(r.Body).Decode(&payload)
		mu.Lock()
		c := payload.Data
		written = &c
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	get := func() *oauth.Credential { mu.Lock(); defer mu.Unlock(); return written }
	return openbao.New(srv.URL, "tok", "secret/test/oauth", "https://base"), get
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

func TestPasteLoginFlow(t *testing.T) {
	bao, written := newMockBao(t)
	fp := &fakePaste{cred: validCred("AT")}
	m := NewManager([]Provider{{Name: "anthropic", Bao: bao, Paste: fp}})

	sess, err := m.StartLogin("anthropic")
	if err != nil {
		t.Fatal(err)
	}
	if sess.Kind != "paste" || sess.AuthURL == "" || sess.State != StatePending {
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
	if w := written(); w == nil || w.Access != "AT" {
		t.Fatalf("OpenBao write=%#v", w)
	}
}

func TestPasteLoginExchangeError(t *testing.T) {
	bao, written := newMockBao(t)
	fp := &fakePaste{err: errors.New("bad code")}
	m := NewManager([]Provider{{Name: "anthropic", Bao: bao, Paste: fp}})
	sess, _ := m.StartLogin("anthropic")
	if err := m.SubmitCode(sess.ID, "x"); err == nil {
		t.Fatal("expected exchange error")
	}
	snap, _ := m.Session(sess.ID)
	if snap.State != StateError {
		t.Errorf("state=%s", snap.State)
	}
	if written() != nil {
		t.Error("must not write to OpenBao on exchange failure")
	}
}

func TestDeviceLoginFlow(t *testing.T) {
	bao, written := newMockBao(t)
	fd := &fakeDevice{interval: time.Millisecond, completeAt: 2, cred: validCred("DAT")}
	m := NewManager([]Provider{{Name: "xai", Bao: bao, Device: fd}})
	m.sleep = func(time.Duration) {} // no real backoff in tests

	sess, err := m.StartLogin("xai")
	if err != nil {
		t.Fatal(err)
	}
	if sess.Kind != "device" || sess.UserCode != "UC-1" || sess.VerificationURI == "" {
		t.Fatalf("sess=%#v", sess)
	}
	waitState(t, m, sess.ID, StateAuthorized)
	if w := written(); w == nil || w.Access != "DAT" {
		t.Fatalf("OpenBao write=%#v", w)
	}
}

func TestDeviceLoginError(t *testing.T) {
	bao, _ := newMockBao(t)
	fd := &fakeDevice{interval: time.Millisecond, failErr: errors.New("device fail")}
	m := NewManager([]Provider{{Name: "xai", Bao: bao, Device: fd}})
	m.sleep = func(time.Duration) {}
	sess, _ := m.StartLogin("xai")
	waitState(t, m, sess.ID, StateError)
}

func TestStartLoginUnknown(t *testing.T) {
	m := NewManager(nil)
	if _, err := m.StartLogin("nope"); err == nil {
		t.Fatal("expected error for unknown provider")
	}
}

func TestProvidersDashboardSeeded(t *testing.T) {
	exp := time.Now().Add(time.Hour).UnixMilli()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"data": map[string]any{
			"access": "AT", "refresh": "RT", "expires": exp,
		}}})
	}))
	t.Cleanup(srv.Close)
	bao := openbao.New(srv.URL, "tok", "secret/x/oauth", "base")
	m := NewManager([]Provider{{Name: "xai", Bao: bao, Device: &fakeDevice{}}})

	views := m.Providers()
	if len(views) != 1 {
		t.Fatalf("views=%d", len(views))
	}
	if !views[0].Seeded || !views[0].TokenValid || views[0].Kind != "device" {
		t.Errorf("view=%#v", views[0])
	}
}
