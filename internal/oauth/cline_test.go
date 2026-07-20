package oauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

// makeJWT builds a minimal JWT whose payload carries the given exp (unix seconds).
// Only the middle segment is parsed by jwtExpiryMillis, so header/sig are dummies.
func makeJWT(expUnix int64) string {
	payload := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"exp":%d,"iss":"https://api.workos.com"}`, expUnix)))
	return "aaaa." + payload + ".bbbb"
}

func TestJWTExpiryMillis(t *testing.T) {
	exp := time.Now().Add(time.Hour).Unix()
	got, err := jwtExpiryMillis(makeJWT(exp))
	if err != nil {
		t.Fatal(err)
	}
	if got != exp*1000 {
		t.Fatalf("exp millis = %d, want %d", got, exp*1000)
	}
	if _, err := jwtExpiryMillis("not-a-jwt"); err == nil {
		t.Error("expected error for malformed jwt")
	}
	if _, err := jwtExpiryMillis(makeJWT(0)); err == nil {
		t.Error("expected error for missing exp")
	}
}

func TestClineRefresh(t *testing.T) {
	exp := time.Now().Add(time.Hour).Unix()
	jwt := makeJWT(exp)
	var form url.Values
	var path, ct string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path, ct = r.URL.Path, r.Header.Get("Content-Type")
		_ = r.ParseForm()
		form = r.Form
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": jwt, "refresh_token": "rotated-rt"})
	}))
	defer srv.Close()

	cred, err := NewCline(srv.URL, "cline-client").Refresh(context.Background(), "old-rt")
	if err != nil {
		t.Fatal(err)
	}
	if path != clineAuthenticatePath {
		t.Errorf("path=%q want %q", path, clineAuthenticatePath)
	}
	if ct != "application/x-www-form-urlencoded" {
		t.Errorf("content-type=%q", ct)
	}
	if form.Get("grant_type") != "refresh_token" || form.Get("client_id") != "cline-client" || form.Get("refresh_token") != "old-rt" {
		t.Errorf("unexpected form: %v", form)
	}
	// Access token MUST be wire-prefixed for api.cline.bot.
	if cred.Access != clineWirePrefix+jwt {
		t.Errorf("access=%q want workos-prefixed jwt", cred.Access)
	}
	if cred.Refresh != "rotated-rt" {
		t.Errorf("refresh=%q want rotated-rt", cred.Refresh)
	}
	wantExp := exp*1000 - clientSkew.Milliseconds()
	if cred.Expires.Int64() != wantExp {
		t.Errorf("expires=%d want %d (jwt exp - skew)", cred.Expires.Int64(), wantExp)
	}
}

func TestClineRefreshKeepsOldRefreshToken(t *testing.T) {
	jwt := makeJWT(time.Now().Add(time.Hour).Unix())
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// No refresh_token in response — client must carry the old one forward.
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": jwt})
	}))
	defer srv.Close()

	cred, err := NewCline(srv.URL, "c").Refresh(context.Background(), "keep-me")
	if err != nil {
		t.Fatal(err)
	}
	if cred.Refresh != "keep-me" {
		t.Errorf("refresh=%q want keep-me", cred.Refresh)
	}
}

func TestClineRefreshErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
	}))
	defer srv.Close()
	if _, err := NewCline(srv.URL, "c").Refresh(context.Background(), "r"); err == nil {
		t.Fatal("expected error on 400")
	}
}

func TestClineDeviceLogin(t *testing.T) {
	jwt := makeJWT(time.Now().Add(time.Hour).Unix())
	var deviceForm, pollForm url.Values
	polls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		switch r.URL.Path {
		case clineDeviceAuthorizePath:
			deviceForm = r.Form
			_ = json.NewEncoder(w).Encode(map[string]any{
				"device_code": "dc", "user_code": "UC-123",
				"verification_uri": "https://cline.bot/device", "expires_in": 300, "interval": 5,
			})
		case clineAuthenticatePath:
			pollForm = r.Form
			polls++
			if polls == 1 {
				http.Error(w, `{"error":"authorization_pending"}`, http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": jwt, "refresh_token": "rt"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	c := NewCline(srv.URL, "cline-client")
	da, err := c.StartDevice(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// WorkOS device authorize carries ONLY client_id (no scope).
	if deviceForm.Get("client_id") != "cline-client" {
		t.Errorf("device form client_id=%q", deviceForm.Get("client_id"))
	}
	if deviceForm.Has("scope") {
		t.Errorf("device form should not send scope: %v", deviceForm)
	}
	if da.DeviceCode != "dc" || da.UserCode != "UC-123" {
		t.Errorf("device auth=%#v", da)
	}

	// First poll: pending.
	if _, st, err := c.PollDevice(context.Background(), "dc"); err != nil || st != PollPending {
		t.Fatalf("first poll st=%v err=%v want pending", st, err)
	}
	// Second poll: complete.
	cred, st, err := c.PollDevice(context.Background(), "dc")
	if err != nil {
		t.Fatal(err)
	}
	if st != PollComplete {
		t.Fatalf("second poll st=%v want complete", st)
	}
	if pollForm.Get("grant_type") != clineDeviceGrant || pollForm.Get("device_code") != "dc" {
		t.Errorf("poll form=%v", pollForm)
	}
	if cred.Access != clineWirePrefix+jwt || cred.Refresh != "rt" {
		t.Errorf("cred=%#v", cred)
	}
}

func TestNewClineDefaults(t *testing.T) {
	c := NewCline("", "")
	if c.WorkOSBase != ClineWorkOSBase {
		t.Errorf("WorkOSBase=%q", c.WorkOSBase)
	}
	if c.ClientID != ClineClientID {
		t.Errorf("ClientID=%q", c.ClientID)
	}
}
