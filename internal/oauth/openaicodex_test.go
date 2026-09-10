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

// codexJWT builds a minimal JWT carrying the chatgpt_account_id claim.
func codexJWT(accountID string) string {
	payload := base64.RawURLEncoding.EncodeToString([]byte(
		fmt.Sprintf(`{"https://api.openai.com/auth":{"chatgpt_account_id":%q}}`, accountID)))
	return "aaaa." + payload + ".bbbb"
}

func TestCodexAccountID(t *testing.T) {
	if got := codexAccountID(codexJWT("acct-1")); got != "acct-1" {
		t.Errorf("accountID=%q want acct-1", got)
	}
	// A non-JWT bearer must not be guessed at — the header is then omitted.
	if got := codexAccountID("sk-not-a-jwt"); got != "" {
		t.Errorf("accountID=%q want empty for non-jwt", got)
	}
	if got := codexAccountID("aaaa.not-base64!!.bbbb"); got != "" {
		t.Errorf("accountID=%q want empty for undecodable payload", got)
	}
}

func TestNewOpenAICodexDefaults(t *testing.T) {
	c := NewOpenAICodex("", "")
	if c.AuthBase != OpenAICodexAuthBase {
		t.Errorf("AuthBase=%q", c.AuthBase)
	}
	if c.ClientID != OpenAICodexClientID {
		t.Errorf("ClientID=%q", c.ClientID)
	}
	if got := c.redirectURI(); got != "https://auth.openai.com/deviceauth/callback" {
		t.Errorf("redirectURI=%q want the registered deviceauth callback", got)
	}
}

func TestOpenAICodexRefresh(t *testing.T) {
	var form url.Values
	var path, ct string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path, ct = r.URL.Path, r.Header.Get("Content-Type")
		_ = r.ParseForm()
		form = r.Form
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "AT-new", "refresh_token": "RT-rotated",
			"id_token": "IT", "expires_in": 3600,
		})
	}))
	defer srv.Close()

	before := time.Now()
	cred, err := NewOpenAICodex(srv.URL, "cid").Refresh(context.Background(), "RT-old")
	if err != nil {
		t.Fatal(err)
	}
	if path != openAICodexTokenPath {
		t.Errorf("path=%q want %q", path, openAICodexTokenPath)
	}
	if ct != "application/x-www-form-urlencoded" {
		t.Errorf("content-type=%q", ct)
	}
	if form.Get("grant_type") != "refresh_token" || form.Get("client_id") != "cid" || form.Get("refresh_token") != "RT-old" {
		t.Errorf("unexpected form: %v", form)
	}
	if cred.Access != "AT-new" {
		t.Errorf("access=%q", cred.Access)
	}
	// OpenAI rotates the refresh token on every exchange.
	if cred.Refresh != "RT-rotated" {
		t.Errorf("refresh=%q want RT-rotated", cred.Refresh)
	}
	wantExp := before.Add(3600*time.Second - clientSkew).UnixMilli()
	if drift := cred.Expires.Int64() - wantExp; drift < 0 || drift > 5000 {
		t.Errorf("expires=%d want ≈%d (expires_in - skew)", cred.Expires.Int64(), wantExp)
	}
}

func TestOpenAICodexRefreshKeepsOldRefreshToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "AT", "expires_in": 3600})
	}))
	defer srv.Close()
	cred, err := NewOpenAICodex(srv.URL, "cid").Refresh(context.Background(), "keep-me")
	if err != nil {
		t.Fatal(err)
	}
	if cred.Refresh != "keep-me" {
		t.Errorf("refresh=%q want keep-me", cred.Refresh)
	}
}

func TestOpenAICodexRefreshErrors(t *testing.T) {
	t.Run("status", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, `{"error":"invalid_grant","error_description":"expired"}`, http.StatusBadRequest)
		}))
		defer srv.Close()
		if _, err := NewOpenAICodex(srv.URL, "cid").Refresh(context.Background(), "r"); err == nil {
			t.Fatal("expected error on 400")
		}
	})
	t.Run("missing expires_in", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "AT", "refresh_token": "RT"})
		}))
		defer srv.Close()
		// Without expires_in the credential would look permanently fresh and
		// never be re-minted, so it must fail loudly instead.
		if _, err := NewOpenAICodex(srv.URL, "cid").Refresh(context.Background(), "r"); err == nil {
			t.Fatal("expected error when expires_in is absent")
		}
	})
}

// codexDeviceServer serves the deviceauth pair + token endpoint. pendingPolls
// device-token calls answer 403 (OpenAI's "authorization pending") before the
// authorization code is handed over.
func codexDeviceServer(t *testing.T, pendingPolls int, interval any) (*httptest.Server, *url.Values, *int) {
	t.Helper()
	var exchange url.Values
	polls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case openAICodexUserCodePath:
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["client_id"] != "cid" {
				t.Errorf("usercode body=%v want client_id=cid", body)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"device_auth_id": "dev-auth-1", "user_code": "ABCD-1234", "interval": interval,
			})
		case openAICodexDeviceTokenPath:
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			// The poll needs BOTH ids; a missing user_code 403s forever upstream.
			if body["device_auth_id"] != "dev-auth-1" || body["user_code"] != "ABCD-1234" {
				t.Errorf("poll body=%v want device_auth_id + user_code", body)
			}
			polls++
			if polls <= pendingPolls {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"authorization_code": "AC-1", "code_verifier": "VER-1",
			})
		case openAICodexTokenPath:
			_ = r.ParseForm()
			exchange = r.Form
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "AT", "refresh_token": "RT", "expires_in": 3600,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	return srv, &exchange, &polls
}

func TestOpenAICodexDeviceLogin(t *testing.T) {
	srv, exchange, _ := codexDeviceServer(t, 1, 5)
	defer srv.Close()
	c := NewOpenAICodex(srv.URL, "cid")

	da, err := c.StartDevice(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if da.DeviceCode != "dev-auth-1" || da.UserCode != "ABCD-1234" {
		t.Fatalf("device auth=%#v", da)
	}
	if da.VerificationURIComplete != srv.URL+openAICodexVerifyPath {
		t.Errorf("verification uri=%q", da.VerificationURIComplete)
	}
	if want := 5*time.Second + openAICodexPollMargin; da.Interval != want {
		t.Errorf("interval=%v want %v (server interval + margin)", da.Interval, want)
	}
	if da.ExpiresAt.IsZero() || !da.ExpiresAt.After(time.Now()) {
		t.Errorf("expiresAt=%v want a future deadline", da.ExpiresAt)
	}

	// 403 is "keep polling", not a failure.
	if _, st, err := c.PollDevice(context.Background(), da); err != nil || st != PollPending {
		t.Fatalf("poll1 st=%v err=%v want pending", st, err)
	}

	cred, st, err := c.PollDevice(context.Background(), da)
	if err != nil {
		t.Fatal(err)
	}
	if st != PollComplete {
		t.Fatalf("poll2 st=%v want complete", st)
	}
	if cred.Access != "AT" || cred.Refresh != "RT" {
		t.Errorf("cred=%#v", cred)
	}
	// The completed poll must exchange the server-minted code + verifier.
	if exchange.Get("grant_type") != "authorization_code" || exchange.Get("code") != "AC-1" ||
		exchange.Get("code_verifier") != "VER-1" || exchange.Get("client_id") != "cid" {
		t.Errorf("exchange form=%v", *exchange)
	}
	if got, want := exchange.Get("redirect_uri"), srv.URL+openAICodexRedirectPath; got != want {
		t.Errorf("exchange redirect_uri=%q want %q", got, want)
	}
}

func TestOpenAICodexDeviceIntervalAsString(t *testing.T) {
	// OpenAI sends `interval` as a JSON string; a numeric-only decode would
	// silently fall back to the default and poll at the wrong rate.
	srv, _, _ := codexDeviceServer(t, 0, "7")
	defer srv.Close()
	da, err := NewOpenAICodex(srv.URL, "cid").StartDevice(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if want := 7*time.Second + openAICodexPollMargin; da.Interval != want {
		t.Errorf("interval=%v want %v", da.Interval, want)
	}
}

func TestOpenAICodexDevicePollHardError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()
	da := DeviceAuth{DeviceCode: "d", UserCode: "u"}
	if _, st, err := NewOpenAICodex(srv.URL, "cid").PollDevice(context.Background(), da); err == nil || st != PollPending {
		t.Fatalf("want hard error, got st=%v err=%v", st, err)
	}
}

func TestOpenAICodexDevicePollIncompleteResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 200 but no code: must NOT be reported as a completed login.
		_ = json.NewEncoder(w).Encode(map[string]any{"authorization_code": "AC"})
	}))
	defer srv.Close()
	da := DeviceAuth{DeviceCode: "d", UserCode: "u"}
	if _, st, err := NewOpenAICodex(srv.URL, "cid").PollDevice(context.Background(), da); err == nil || st == PollComplete {
		t.Fatalf("want error, got st=%v err=%v", st, err)
	}
}

func TestCodexUsageRoot(t *testing.T) {
	cases := map[string]string{
		"":                                      OpenAICodexBaseURL,
		"https://chatgpt.com/backend-api":       "https://chatgpt.com/backend-api",
		"https://chatgpt.com/backend-api/":      "https://chatgpt.com/backend-api",
		"https://chatgpt.com/backend-api/codex": "https://chatgpt.com/backend-api",
		"https://chatgpt.com/backend-api/codex/responses": "https://chatgpt.com/backend-api",
		"https://chat.openai.com/backend-api/codex":       "https://chat.openai.com/backend-api",
		"not a url": OpenAICodexBaseURL,
	}
	for in, want := range cases {
		if got := codexUsageRoot(in); got != want {
			t.Errorf("codexUsageRoot(%q)=%q want %q", in, got, want)
		}
	}
}

func TestCodexProbeUsage(t *testing.T) {
	var path, auth, acct string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path, auth, acct = r.URL.Path, r.Header.Get("Authorization"), r.Header.Get("ChatGPT-Account-Id")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"plan_type": "pro",
			"rate_limit": map[string]any{
				"allowed":       true,
				"limit_reached": false,
				"primary_window": map[string]any{
					"used_percent": 12.5, "limit_window_seconds": 18000, "reset_after_seconds": 600,
				},
				"secondary_window": map[string]any{
					"used_percent": 40, "limit_window_seconds": 604800, "reset_at": 1893456000,
				},
			},
		})
	}))
	defer srv.Close()

	token := codexJWT("acct-9")
	u := CodexProber{BaseURL: srv.URL}.ProbeUsage(context.Background(), token)
	if u.Err != "" {
		t.Fatalf("probe err=%q", u.Err)
	}
	if path != openAICodexUsagePath {
		t.Errorf("path=%q want %q", path, openAICodexUsagePath)
	}
	if auth != "Bearer "+token {
		t.Errorf("authorization=%q", auth)
	}
	// The ChatGPT backend scopes usage per workspace.
	if acct != "acct-9" {
		t.Errorf("account header=%q want acct-9", acct)
	}
	if u.Window5hUtil != "0.1250" || u.Window7dUtil != "0.4000" {
		t.Errorf("windows 5h=%q 7d=%q", u.Window5hUtil, u.Window7dUtil)
	}
	if u.Window7dReset != "1893456000" {
		t.Errorf("7d reset=%q want the reset_at stamp", u.Window7dReset)
	}
	if u.Window5hReset == "" {
		t.Error("5h reset empty: reset_after_seconds should resolve to a stamp")
	}
	if u.Status != "" {
		t.Errorf("status=%q want empty while allowed and under the limit", u.Status)
	}
	// Auto-switch ranks accounts on the worst window, so the mapping above has
	// to be visible through WorstUtilPercent.
	if pct, ok := WorstUtilPercent(u); !ok || pct != 40 {
		t.Errorf("WorstUtilPercent=%d ok=%v want 40 true", pct, ok)
	}
}

func TestCodexProbeUsageLimitReached(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"rate_limit": map[string]any{
				"allowed":        true,
				"limit_reached":  true,
				"primary_window": map[string]any{"used_percent": 100},
			},
		})
	}))
	defer srv.Close()
	u := CodexProber{BaseURL: srv.URL}.ProbeUsage(context.Background(), "AT")
	if u.Status != "rejected" {
		t.Errorf("status=%q want rejected", u.Status)
	}
	if u.Window5hUtil != "1.0000" {
		t.Errorf("5h util=%q want 1.0000", u.Window5hUtil)
	}
}

func TestCodexProbeUsageFailures(t *testing.T) {
	t.Run("http error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "nope", http.StatusUnauthorized)
		}))
		defer srv.Close()
		if u := (CodexProber{BaseURL: srv.URL}).ProbeUsage(context.Background(), "AT"); u.Err != "HTTP 401" {
			t.Errorf("err=%q want HTTP 401", u.Err)
		}
	})
	t.Run("no rate_limit", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]any{"plan_type": "free"})
		}))
		defer srv.Close()
		// An empty payload must read as unknown, never as a free quota:
		// auto-switch would otherwise hand the active role to a dead account.
		u := (CodexProber{BaseURL: srv.URL}).ProbeUsage(context.Background(), "AT")
		if u.Err == "" {
			t.Fatal("want an error for a payload with no rate_limit")
		}
		if _, ok := WorstUtilPercent(u); ok {
			t.Error("WorstUtilPercent must report unknown, not headroom")
		}
	})
	t.Run("no window", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]any{"rate_limit": map[string]any{"allowed": true}})
		}))
		defer srv.Close()
		u := (CodexProber{BaseURL: srv.URL}).ProbeUsage(context.Background(), "AT")
		if u.Err == "" {
			t.Fatal("want an error for a rate_limit with no windows")
		}
	})
}
