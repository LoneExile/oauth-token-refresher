package web

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// serve registers the manager on a fresh mux behind an httptest server.
func serve(t *testing.T, m *Manager) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	Register(mux, m)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// noRedirectClient stops the http client following 3xx so we can assert on the
// redirect itself.
func noRedirectClient() *http.Client {
	return &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func TestDashboardRenders(t *testing.T) {
	v := newFakeVault(t)
	bao := v.client("secret/anthropic/oauth", "https://base")
	fp := &fakePaste{}
	m := NewManager([]Provider{{Name: "anthropic", Bao: bao, Paste: fp}})
	addAccount(t, m, fp, "anthropic", "alice", "ALICE") // active
	addAccount(t, m, fp, "anthropic", "bob", "BOB")     // inactive → shows "Switch to"
	srv := serve(t, m)

	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("dashboard status=%d", resp.StatusCode)
	}
	for _, want := range []string{"anthropic", "alice", "bob", "active", "Add account", "Switch to", "Re-login", "Remove"} {
		if !strings.Contains(string(body), want) {
			t.Errorf("dashboard missing %q\n%s", want, body)
		}
	}
}

func TestAddAccountRedirectsToSession(t *testing.T) {
	v := newFakeVault(t)
	bao := v.client("secret/anthropic/oauth", "https://base")
	m := NewManager([]Provider{{Name: "anthropic", Bao: bao, Paste: &fakePaste{cred: validCred("AT")}}})
	srv := serve(t, m)

	resp, err := noRedirectClient().PostForm(srv.URL+"/login/anthropic", url.Values{"label": {"friend"}})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); !strings.HasPrefix(loc, "/session/") {
		t.Fatalf("redirect location=%q", loc)
	}
}

func TestActivateAndRemoveRoutes(t *testing.T) {
	v := newFakeVault(t)
	bao := v.client("secret/anthropic/oauth", "https://base")
	fp := &fakePaste{}
	m := NewManager([]Provider{{Name: "anthropic", Bao: bao, Paste: fp}})
	alice := addAccount(t, m, fp, "anthropic", "alice", "ALICE")
	bob := addAccount(t, m, fp, "anthropic", "bob", "BOB")
	srv := serve(t, m)
	client := noRedirectClient()

	// Switch to bob via the HTTP route.
	resp, err := client.PostForm(srv.URL+"/account/anthropic/"+bob+"/activate", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("activate status=%d", resp.StatusCode)
	}
	if c, _ := v.cred("secret/anthropic/oauth"); c.Access != "BOB" {
		t.Fatalf("live should be BOB after activate route, got %q", c.Access)
	}

	// Remove alice via the HTTP route.
	resp, err = client.PostForm(srv.URL+"/account/anthropic/"+alice+"/remove", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("remove status=%d", resp.StatusCode)
	}
	if reg, _ := v.registry("secret/anthropic/registry"); reg.Has(alice) {
		t.Fatal("alice should be gone after remove route")
	}
}
