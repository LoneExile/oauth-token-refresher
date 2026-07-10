package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestGeneratePKCE(t *testing.T) {
	p, err := GeneratePKCE()
	if err != nil {
		t.Fatal(err)
	}
	vb, err := base64.RawURLEncoding.DecodeString(p.Verifier)
	if err != nil {
		t.Fatalf("verifier not base64url: %v", err)
	}
	if len(vb) != 96 {
		t.Errorf("verifier bytes=%d want 96", len(vb))
	}
	sum := sha256.Sum256([]byte(p.Verifier))
	if p.Challenge != base64.RawURLEncoding.EncodeToString(sum[:]) {
		t.Error("challenge != base64url(sha256(verifier))")
	}
	if p2, _ := GeneratePKCE(); p2.Verifier == p.Verifier {
		t.Error("verifier not random")
	}
}

func TestGenerateState(t *testing.T) {
	s, err := GenerateState()
	if err != nil {
		t.Fatal(err)
	}
	if len(s) != 32 { // 16 bytes hex
		t.Errorf("state len=%d want 32", len(s))
	}
	if s2, _ := GenerateState(); s == s2 {
		t.Error("state not random")
	}
}

func TestXAIStartDevice(t *testing.T) {
	var form url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth2/device/code" {
			t.Errorf("path=%s", r.URL.Path)
		}
		_ = r.ParseForm()
		form = r.Form
		_ = json.NewEncoder(w).Encode(map[string]any{
			"device_code":               "dc",
			"user_code":                 "WXYZ-1234",
			"verification_uri":          "https://x.ai/device",
			"verification_uri_complete": "https://x.ai/device?code=WXYZ-1234",
			"expires_in":                600,
			"interval":                  5,
		})
	}))
	defer srv.Close()

	da, err := NewXAI(srv.URL, "cid").StartDevice(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if form.Get("client_id") != "cid" || form.Get("scope") != XAIScope {
		t.Errorf("form=%v", form)
	}
	if da.DeviceCode != "dc" || da.UserCode != "WXYZ-1234" || da.VerificationURIComplete == "" {
		t.Errorf("da=%#v", da)
	}
	if da.Interval != 5*time.Second {
		t.Errorf("interval=%v", da.Interval)
	}
}

// xaiDeviceTokenServer serves OIDC discovery + a token endpoint whose behavior
// is driven by the supplied handler.
func xaiDeviceTokenServer(t *testing.T, token http.HandlerFunc) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			_ = json.NewEncoder(w).Encode(map[string]string{"token_endpoint": srv.URL + "/token"})
			return
		}
		token(w, r)
	}))
	return srv
}

func TestXAIPollDeviceStates(t *testing.T) {
	step := 0
	srv := xaiDeviceTokenServer(t, func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:device_code" || r.Form.Get("device_code") != "dc" {
			t.Errorf("form=%v", r.Form)
		}
		step++
		switch step {
		case 1:
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "authorization_pending"})
		case 2:
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "slow_down"})
		default:
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "AT", "refresh_token": "RT", "expires_in": 3600})
		}
	})
	defer srv.Close()
	c := NewXAI(srv.URL, "cid")

	if _, st, err := c.PollDevice(context.Background(), "dc"); err != nil || st != PollPending {
		t.Fatalf("poll1 want pending: st=%v err=%v", st, err)
	}
	if _, st, err := c.PollDevice(context.Background(), "dc"); err != nil || st != PollSlowDown {
		t.Fatalf("poll2 want slow_down: st=%v err=%v", st, err)
	}
	cred, st, err := c.PollDevice(context.Background(), "dc")
	if err != nil || st != PollComplete {
		t.Fatalf("poll3 want complete: st=%v err=%v", st, err)
	}
	if cred.Access != "AT" || cred.Refresh != "RT" {
		t.Errorf("cred=%#v", cred)
	}
}

func TestXAIPollDeviceHardError(t *testing.T) {
	srv := xaiDeviceTokenServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "access_denied", "error_description": "user denied"})
	})
	defer srv.Close()
	if _, st, err := NewXAI(srv.URL, "cid").PollDevice(context.Background(), "dc"); err == nil || st != PollPending {
		t.Fatalf("want hard error, got st=%v err=%v", st, err)
	}
}

func TestAnthropicAuthURL(t *testing.T) {
	c := NewAnthropic("", "")
	u := c.AuthURL(PKCE{Challenge: "CHAL"}, "STATE")
	if !strings.HasPrefix(u, AnthropicAuthorizeURL+"?") {
		t.Fatalf("prefix: %s", u)
	}
	q, err := url.Parse(u)
	if err != nil {
		t.Fatal(err)
	}
	p := q.Query()
	for k, want := range map[string]string{
		"client_id":             AnthropicClientID,
		"response_type":         "code",
		"code":                  "true",
		"code_challenge":        "CHAL",
		"code_challenge_method": "S256",
		"state":                 "STATE",
		"redirect_uri":          AnthropicRedirectURI,
		"scope":                 AnthropicScope,
	} {
		if got := p.Get(k); got != want {
			t.Errorf("param %s=%q want %q", k, got, want)
		}
	}
}

func TestAnthropicExchangeCode(t *testing.T) {
	var body map[string]string
	var beta string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		beta = r.Header.Get("anthropic-beta")
		_ = json.NewDecoder(r.Body).Decode(&body)
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "AT", "refresh_token": "RT", "expires_in": 3600})
	}))
	defer srv.Close()

	c := NewAnthropic(srv.URL, "cid")
	cred, err := c.ExchangeCode(context.Background(), "AUTHCODE#RETURNEDSTATE", "origstate", PKCE{Verifier: "VER"})
	if err != nil {
		t.Fatal(err)
	}
	if body["grant_type"] != "authorization_code" {
		t.Errorf("grant_type=%q", body["grant_type"])
	}
	if body["code"] != "AUTHCODE" {
		t.Errorf("code=%q (must strip #state)", body["code"])
	}
	if body["state"] != "RETURNEDSTATE" {
		t.Errorf("state=%q (fragment overrides arg)", body["state"])
	}
	if body["code_verifier"] != "VER" {
		t.Errorf("code_verifier=%q", body["code_verifier"])
	}
	if body["redirect_uri"] != AnthropicRedirectURI {
		t.Errorf("redirect_uri=%q", body["redirect_uri"])
	}
	if beta != "" {
		t.Errorf("code exchange must NOT send anthropic-beta, got %q", beta)
	}
	if cred.Access != "AT" || cred.Refresh != "RT" {
		t.Errorf("cred=%#v", cred)
	}
}
