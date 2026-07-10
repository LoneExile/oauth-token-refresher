package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestNeedsRefresh(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name string
		cred Credential
		skew time.Duration
		want bool
	}{
		{"fresh", Credential{Access: "a", Refresh: "r", Expires: FlexInt64(now.Add(2 * time.Hour).UnixMilli())}, 10 * time.Minute, false},
		{"within skew", Credential{Access: "a", Refresh: "r", Expires: FlexInt64(now.Add(5 * time.Minute).UnixMilli())}, 10 * time.Minute, true},
		{"expired", Credential{Access: "a", Refresh: "r", Expires: FlexInt64(now.Add(-time.Minute).UnixMilli())}, 10 * time.Minute, true},
		{"no refresh", Credential{Access: "a", Refresh: "", Expires: FlexInt64(now.Add(-time.Minute).UnixMilli())}, 10 * time.Minute, false},
		{"empty access", Credential{Access: "", Refresh: "r", Expires: FlexInt64(now.Add(2 * time.Hour).UnixMilli())}, 10 * time.Minute, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := NeedsRefresh(tc.cred, tc.skew); got != tc.want {
				t.Fatalf("NeedsRefresh()=%v want %v", got, tc.want)
			}
		})
	}
}

func TestFlexInt64JSON(t *testing.T) {
	var c Credential
	if err := json.Unmarshal([]byte(`{"access":"a","refresh":"r","expires":"123"}`), &c); err != nil {
		t.Fatal(err)
	}
	if c.Expires.Int64() != 123 {
		t.Fatalf("string expires: got %d", c.Expires.Int64())
	}
	if err := json.Unmarshal([]byte(`{"access":"a","refresh":"r","expires":456}`), &c); err != nil {
		t.Fatal(err)
	}
	if c.Expires.Int64() != 456 {
		t.Fatalf("number expires: got %d", c.Expires.Int64())
	}
}

// assertExpirySkew checks expires ≈ [before, after] + expiresIn − 5m clientSkew.
func assertExpirySkew(t *testing.T, expiresMs int64, before, after time.Time, expiresIn time.Duration) {
	t.Helper()
	lo := before.Add(expiresIn - clientSkew).UnixMilli()
	hi := after.Add(expiresIn - clientSkew).UnixMilli()
	if expiresMs < lo || expiresMs > hi {
		t.Errorf("expires=%d not in [%d,%d] (expiresIn=%s skew=%s)", expiresMs, lo, hi, expiresIn, clientSkew)
	}
}

func TestAnthropicRefresh(t *testing.T) {
	var body map[string]string
	var beta, ua, ct string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method=%s want POST", r.Method)
		}
		beta, ua, ct = r.Header.Get("anthropic-beta"), r.Header.Get("User-Agent"), r.Header.Get("Content-Type")
		_ = json.NewDecoder(r.Body).Decode(&body)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "new-access", "refresh_token": "new-refresh", "expires_in": 3600, "token_type": "Bearer",
		})
	}))
	defer srv.Close()

	c := NewAnthropic(srv.URL, "test-client")
	before := time.Now()
	cred, err := c.Refresh(context.Background(), "old-refresh")
	after := time.Now()
	if err != nil {
		t.Fatal(err)
	}

	if body["grant_type"] != "refresh_token" || body["client_id"] != "test-client" || body["refresh_token"] != "old-refresh" {
		t.Errorf("unexpected body: %#v", body)
	}
	if beta != "oauth-2025-04-20" {
		t.Errorf("anthropic-beta=%q", beta)
	}
	if ct != "application/json" {
		t.Errorf("content-type=%q", ct)
	}
	if ua == "" {
		t.Error("missing User-Agent")
	}
	if cred.Access != "new-access" || cred.Refresh != "new-refresh" {
		t.Errorf("cred=%#v", cred)
	}
	assertExpirySkew(t, cred.Expires.Int64(), before, after, 3600*time.Second)
}

func TestAnthropicRefreshKeepsOldRefreshToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// No refresh_token in response — client must carry the old one forward.
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "a", "expires_in": 3600})
	}))
	defer srv.Close()

	cred, err := NewAnthropic(srv.URL, "c").Refresh(context.Background(), "keep-me")
	if err != nil {
		t.Fatal(err)
	}
	if cred.Refresh != "keep-me" {
		t.Errorf("refresh=%q want keep-me", cred.Refresh)
	}
}

func TestAnthropicRefreshErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
	}))
	defer srv.Close()
	if _, err := NewAnthropic(srv.URL, "c").Refresh(context.Background(), "r"); err == nil {
		t.Fatal("expected error on 400")
	}
}

func TestNewAnthropicDefaults(t *testing.T) {
	c := NewAnthropic("", "")
	if c.TokenURL != AnthropicTokenURL {
		t.Errorf("TokenURL=%q", c.TokenURL)
	}
	if c.ClientID != AnthropicClientID {
		t.Errorf("ClientID=%q", c.ClientID)
	}
}

func TestXAIRefresh(t *testing.T) {
	var form url.Values
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]string{"token_endpoint": srv.URL + "/token"})
		case "/token":
			_ = r.ParseForm()
			form = r.Form
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "xa", "refresh_token": "xr", "expires_in": 7200})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	before := time.Now()
	cred, err := NewXAI(srv.URL, "xai-client").Refresh(context.Background(), "old-xr")
	after := time.Now()
	if err != nil {
		t.Fatal(err)
	}
	if form.Get("grant_type") != "refresh_token" || form.Get("client_id") != "xai-client" || form.Get("refresh_token") != "old-xr" {
		t.Errorf("unexpected form: %v", form)
	}
	if cred.Access != "xa" || cred.Refresh != "xr" {
		t.Errorf("cred=%#v", cred)
	}
	assertExpirySkew(t, cred.Expires.Int64(), before, after, 7200*time.Second)
}
