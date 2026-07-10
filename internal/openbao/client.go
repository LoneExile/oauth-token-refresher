package openbao

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/LoneExile/oauth-token-refresher/internal/oauth"
)

// Client talks to OpenBao's (or HashiCorp Vault's) KV v2 HTTP API.
type Client struct {
	Addr    string
	Token   string
	KVPath  string // mount/path without /data/, e.g. secret/xai/oauth
	BaseURL string
	HTTP    *http.Client
}

func New(addr, token, kvPath, baseURL string) *Client {
	return &Client{
		Addr:    strings.TrimRight(addr, "/"),
		Token:   token,
		KVPath:  strings.Trim(kvPath, "/"),
		BaseURL: baseURL,
		HTTP:    &http.Client{Timeout: 20 * time.Second},
	}
}

func (c *Client) dataURL() string {
	// KV v2 read/write: /v1/<mount>/data/<path>
	parts := strings.SplitN(c.KVPath, "/", 2)
	if len(parts) != 2 {
		return c.Addr + "/v1/" + c.KVPath
	}
	return c.Addr + "/v1/" + parts[0] + "/data/" + parts[1]
}

type kvRead struct {
	Data struct {
		Data oauth.Credential `json:"data"`
	} `json:"data"`
}

func (c *Client) ReadCredential(ctx context.Context) (oauth.Credential, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.dataURL(), nil)
	if err != nil {
		return oauth.Credential{}, err
	}
	req.Header.Set("X-Vault-Token", c.Token)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return oauth.Credential{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode == http.StatusNotFound {
		return oauth.Credential{}, fmt.Errorf("openbao: secret not found at %s (seed refresh token first)", c.KVPath)
	}
	if resp.StatusCode != http.StatusOK {
		return oauth.Credential{}, fmt.Errorf("openbao read: status %d: %s", resp.StatusCode, string(body))
	}
	var out kvRead
	if err := json.Unmarshal(body, &out); err != nil {
		return oauth.Credential{}, err
	}
	return out.Data.Data, nil
}

func (c *Client) WriteCredential(ctx context.Context, cred oauth.Credential) error {
	payload := map[string]any{
		"data": map[string]any{
			"access":     cred.Access,
			"refresh":    cred.Refresh,
			"expires":    cred.Expires.Int64(),
			"base_url":   c.BaseURL,
			"updated_at": time.Now().UTC().Format(time.RFC3339),
		},
	}
	raw, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.dataURL(), bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("X-Vault-Token", c.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("openbao write: status %d: %s", resp.StatusCode, string(body))
	}
	return nil
}
