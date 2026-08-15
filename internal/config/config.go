package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// ProviderConfig describes one OAuth provider the refresher manages. Each
// provider has its own OpenBao KV path and base_url so multiple credentials can
// be kept fresh by a single process.
type ProviderConfig struct {
	Name    string // metric label + log field, e.g. "xai" or "anthropic"
	Type    string // refresher implementation: "xai" (OIDC) or "anthropic"
	KVPath  string // KV v2 path without /data/, e.g. secret/xai/oauth
	BaseURL string // written to KV as base_url for consumers

	// xAI (OIDC discovery + device login) fields.
	Issuer string
	Scope  string // device-login scope; empty uses the provider default

	// Shared: OAuth client ID. Empty uses the provider default (Anthropic only).
	ClientID string

	// Anthropic fields. Empty uses the provider default.
	TokenURL    string
	RedirectURI string // paste-login redirect URI; empty uses the provider default
}

// Config is env-driven runtime configuration for the refresher. Writes only to
// OpenBao (Vault-compatible); consumers sync via External Secrets Operator or
// any Vault KV consumer. No direct Kubernetes API writes.
type Config struct {
	Providers []ProviderConfig

	// OpenBao / Vault
	OpenBaoAddr  string
	OpenBaoToken string

	RefreshSkew  time.Duration
	LoopInterval time.Duration
	Once         bool
	ListenAddr   string

	// LoginUI serves the self-service OAuth login frontend.
	LoginUI bool

	// AutoSwitch moves the active account to one with more headroom when the
	// active account's quota is nearly spent. Opt-in: empty AUTOSWITCH_PROVIDERS
	// disables it entirely, so an unconfigured deployment behaves exactly as
	// before.
	AutoSwitchProviders []string
	AutoSwitchInterval  time.Duration
	AutoSwitchTriggerP  int
	AutoSwitchMarginP   int
	AutoSwitchCooldown  time.Duration
}

func FromEnv() (Config, error) {
	c := Config{
		OpenBaoAddr:  env("OPENBAO_ADDR", "http://localhost:8200"),
		OpenBaoToken: os.Getenv("OPENBAO_TOKEN"),
		RefreshSkew:  durationEnv("REFRESH_SKEW", 10*time.Minute),
		LoopInterval: durationEnv("LOOP_INTERVAL", 60*time.Second),
		Once:         boolEnv("ONCE", false),
		ListenAddr:   env("LISTEN_ADDR", ":8080"),
		LoginUI:      boolEnv("LOGIN_UI_ENABLED", true),
		// Trigger at 80 rather than nearer the ceiling: a switch only reaches
		// consumers after OpenBao -> ESO -> kubelet republishes the mounted
		// secret, so handing over at 99% would hand over an account that is
		// already failing. Margin 15 keeps three near-equal accounts from
		// passing the active role in circles.
		AutoSwitchProviders: listEnv("AUTOSWITCH_PROVIDERS"),
		AutoSwitchInterval:  durationEnv("AUTOSWITCH_INTERVAL", 5*time.Minute),
		AutoSwitchTriggerP:  intEnv("AUTOSWITCH_TRIGGER_PCT", 80),
		AutoSwitchMarginP:   intEnv("AUTOSWITCH_MARGIN_PCT", 15),
		AutoSwitchCooldown:  durationEnv("AUTOSWITCH_COOLDOWN", 15*time.Minute),
	}
	if c.OpenBaoToken == "" {
		return c, fmt.Errorf("OPENBAO_TOKEN is required")
	}

	// xAI — enabled by default (backward compatible). Legacy OPENBAO_KV_PATH /
	// BASE_URL are honored as the xAI KV path / base URL.
	if boolEnv("XAI_ENABLED", true) {
		clientID := env("XAI_CLIENT_ID", "b1a00492-073a-47ea-816f-4c329264a828")
		if clientID == "" {
			return c, fmt.Errorf("XAI_CLIENT_ID is required when xAI is enabled")
		}
		c.Providers = append(c.Providers, ProviderConfig{
			Name:     "xai",
			Type:     "xai",
			KVPath:   firstEnv("secret/xai/oauth", "XAI_KV_PATH", "OPENBAO_KV_PATH"),
			BaseURL:  firstEnv("https://api.x.ai/v1", "XAI_BASE_URL", "BASE_URL"),
			Issuer:   env("XAI_ISSUER", "https://auth.x.ai"),
			ClientID: clientID,
			Scope:    env("XAI_SCOPE", ""),
		})
	}

	// Anthropic (Claude Pro/Max) — opt-in. Client ID / token URL default inside
	// the oauth.AnthropicClient when left empty.
	if boolEnv("ANTHROPIC_ENABLED", false) {
		c.Providers = append(c.Providers, ProviderConfig{
			Name:        "anthropic",
			Type:        "anthropic",
			KVPath:      env("ANTHROPIC_KV_PATH", "secret/anthropic/oauth"),
			BaseURL:     env("ANTHROPIC_BASE_URL", "https://api.anthropic.com"),
			ClientID:    os.Getenv("ANTHROPIC_CLIENT_ID"),
			TokenURL:    os.Getenv("ANTHROPIC_TOKEN_URL"),
			RedirectURI: os.Getenv("ANTHROPIC_REDIRECT_URI"),
		})
	}

	// Cline (ClinePass) — opt-in. WorkOS device login + refresh; the access
	// token is stored wire-prefixed (`workos:`) for api.cline.bot. Client ID /
	// WorkOS base default inside oauth.NewCline when left empty.
	if boolEnv("CLINE_ENABLED", false) {
		c.Providers = append(c.Providers, ProviderConfig{
			Name:     "cline",
			Type:     "cline",
			KVPath:   env("CLINE_KV_PATH", "secret/cline/oauth"),
			BaseURL:  env("CLINE_BASE_URL", "https://api.cline.bot/api/v1"),
			Issuer:   env("CLINE_WORKOS_BASE", "https://api.workos.com"),
			ClientID: os.Getenv("CLINE_CLIENT_ID"),
		})
	}

	if len(c.Providers) == 0 {
		return c, fmt.Errorf("no providers enabled (set XAI_ENABLED=true or ANTHROPIC_ENABLED=true)")
	}
	return c, nil
}

func env(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

// firstEnv returns the first non-empty env var among keys, else def.
func firstEnv(def string, keys ...string) string {
	for _, k := range keys {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return v
		}
	}
	return def
}

func durationEnv(k string, def time.Duration) time.Duration {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return def
	}
	return d
}

func boolEnv(k string, def bool) bool {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}

// intEnv reads a plain integer, falling back to def on anything unparseable so
// a typo cannot silently disable a threshold by turning it into 0 (a 0 trigger
// would switch accounts constantly).
func intEnv(k string, def int) int {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

// listEnv reads a comma-separated list, dropping blanks. An unset or empty
// value yields nil, which is what keeps the feature opt-in.
func listEnv(k string) []string {
	var out []string
	for _, part := range strings.Split(os.Getenv(k), ",") {
		if s := strings.TrimSpace(part); s != "" {
			out = append(out, s)
		}
	}
	return out
}
