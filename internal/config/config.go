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
