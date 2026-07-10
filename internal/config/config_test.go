package config

import "testing"

// clearEnv neutralizes every env var FromEnv reads so tests are deterministic
// regardless of the ambient environment (e.g. a developer's ANTHROPIC_BASE_URL).
// Empty values are treated as unset by env/firstEnv/boolEnv/durationEnv.
func clearEnv(t *testing.T) {
	for _, k := range []string{
		"OPENBAO_ADDR", "OPENBAO_TOKEN", "OPENBAO_KV_PATH",
		"XAI_ENABLED", "XAI_CLIENT_ID", "XAI_KV_PATH", "XAI_BASE_URL", "XAI_ISSUER", "BASE_URL",
		"ANTHROPIC_ENABLED", "ANTHROPIC_KV_PATH", "ANTHROPIC_BASE_URL", "ANTHROPIC_CLIENT_ID", "ANTHROPIC_TOKEN_URL",
		"REFRESH_SKEW", "LOOP_INTERVAL", "ONCE", "LISTEN_ADDR",
	} {
		t.Setenv(k, "")
	}
}

func find(c Config, name string) *ProviderConfig {
	for i := range c.Providers {
		if c.Providers[i].Name == name {
			return &c.Providers[i]
		}
	}
	return nil
}

func TestFromEnvBackwardCompatXAIOnly(t *testing.T) {
	clearEnv(t)
	t.Setenv("OPENBAO_TOKEN", "tok")
	c, err := FromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Providers) != 1 {
		t.Fatalf("providers=%d want 1", len(c.Providers))
	}
	p := c.Providers[0]
	if p.Name != "xai" || p.Type != "xai" {
		t.Errorf("provider=%s/%s", p.Name, p.Type)
	}
	if p.KVPath != "secret/xai/oauth" {
		t.Errorf("kvpath=%q", p.KVPath)
	}
	if p.BaseURL != "https://api.x.ai/v1" {
		t.Errorf("baseurl=%q", p.BaseURL)
	}
	if p.Issuer != "https://auth.x.ai" {
		t.Errorf("issuer=%q", p.Issuer)
	}
}

func TestFromEnvLegacyEnvNames(t *testing.T) {
	clearEnv(t)
	t.Setenv("OPENBAO_TOKEN", "tok")
	t.Setenv("OPENBAO_KV_PATH", "secret/custom/xai")
	t.Setenv("BASE_URL", "https://gw/v1")
	c, err := FromEnv()
	if err != nil {
		t.Fatal(err)
	}
	p := find(c, "xai")
	if p == nil {
		t.Fatal("no xai provider")
	}
	if p.KVPath != "secret/custom/xai" {
		t.Errorf("kvpath=%q (legacy OPENBAO_KV_PATH not honored)", p.KVPath)
	}
	if p.BaseURL != "https://gw/v1" {
		t.Errorf("baseurl=%q (legacy BASE_URL not honored)", p.BaseURL)
	}
}

func TestFromEnvAnthropicOptIn(t *testing.T) {
	clearEnv(t)
	t.Setenv("OPENBAO_TOKEN", "tok")
	t.Setenv("ANTHROPIC_ENABLED", "true")
	c, err := FromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Providers) != 2 {
		t.Fatalf("providers=%d want 2", len(c.Providers))
	}
	a := find(c, "anthropic")
	if a == nil {
		t.Fatal("no anthropic provider")
	}
	if a.Type != "anthropic" {
		t.Errorf("type=%q", a.Type)
	}
	if a.KVPath != "secret/anthropic/oauth" {
		t.Errorf("kvpath=%q", a.KVPath)
	}
	if a.BaseURL != "https://api.anthropic.com" {
		t.Errorf("baseurl=%q", a.BaseURL)
	}
	// ClientID/TokenURL default inside oauth.NewAnthropic when empty.
	if a.ClientID != "" || a.TokenURL != "" {
		t.Errorf("expected empty client/token overrides, got %q / %q", a.ClientID, a.TokenURL)
	}
}

func TestFromEnvAnthropicOnly(t *testing.T) {
	clearEnv(t)
	t.Setenv("OPENBAO_TOKEN", "tok")
	t.Setenv("XAI_ENABLED", "false")
	t.Setenv("ANTHROPIC_ENABLED", "true")
	c, err := FromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Providers) != 1 || c.Providers[0].Name != "anthropic" {
		t.Fatalf("providers=%v", c.Providers)
	}
}

func TestFromEnvNoProvidersErrors(t *testing.T) {
	clearEnv(t)
	t.Setenv("OPENBAO_TOKEN", "tok")
	t.Setenv("XAI_ENABLED", "false")
	if _, err := FromEnv(); err == nil {
		t.Fatal("expected error when no providers enabled")
	}
}

func TestFromEnvMissingTokenErrors(t *testing.T) {
	clearEnv(t)
	if _, err := FromEnv(); err == nil {
		t.Fatal("expected error when OPENBAO_TOKEN missing")
	}
}
