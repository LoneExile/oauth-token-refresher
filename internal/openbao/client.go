package openbao

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/LoneExile/oauth-token-refresher/internal/oauth"
)

// ErrNotFound is returned when a KV path holds no secret (HTTP 404). Callers use
// errors.Is to tell "unseeded" apart from a transport / permission failure.
var ErrNotFound = errors.New("openbao: secret not found")

// Client talks to OpenBao's (or HashiCorp Vault's) KV v2 HTTP API.
//
// One Client is bound to a single provider. KVPath is the LIVE credential path
// consumed downstream (ESO → LiteLLM); it always mirrors the active account.
// Base is the shared prefix under which per-account credentials and the account
// registry live:
//
//	KVPath                  secret/anthropic/oauth          (live = active account)
//	Base + /accounts/<id>   secret/anthropic/accounts/<id>  (one per account)
//	Base + /registry        secret/anthropic/registry       (active id + accounts)
type Client struct {
	Addr    string
	Token   string
	KVPath  string // mount/path without /data/, e.g. secret/anthropic/oauth
	Base    string // KVPath minus its final segment, e.g. secret/anthropic
	BaseURL string
	HTTP    *http.Client
}

func New(addr, token, kvPath, baseURL string) *Client {
	kvPath = strings.Trim(kvPath, "/")
	return &Client{
		Addr:    strings.TrimRight(addr, "/"),
		Token:   token,
		KVPath:  kvPath,
		Base:    basePrefix(kvPath),
		BaseURL: baseURL,
		HTTP:    &http.Client{Timeout: 20 * time.Second},
	}
}

// basePrefix drops the final path segment (secret/anthropic/oauth → secret/anthropic).
func basePrefix(p string) string {
	if i := strings.LastIndex(p, "/"); i > 0 {
		return p[:i]
	}
	return p
}

// AccountPath is the KV path storing one account's credential.
func (c *Client) AccountPath(id string) string { return c.Base + "/accounts/" + id }

// registryPath is the KV path storing the account registry.
func (c *Client) registryPath() string { return c.Base + "/registry" }

// kvURL builds a KV v2 API URL for the given engine kind ("data" | "metadata")
// and logical path (mount/rest). A single-segment path is passed through as-is.
func (c *Client) kvURL(kind, logical string) string {
	logical = strings.Trim(logical, "/")
	parts := strings.SplitN(logical, "/", 2)
	if len(parts) != 2 {
		return c.Addr + "/v1/" + logical
	}
	return c.Addr + "/v1/" + parts[0] + "/" + kind + "/" + parts[1]
}

// do issues an authenticated request and returns the (capped) body + status.
func (c *Client) do(ctx context.Context, method, url string, body []byte) ([]byte, int, error) {
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, r)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("X-Vault-Token", c.Token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return out, resp.StatusCode, nil
}

type kvRead struct {
	Data struct {
		Data oauth.Credential `json:"data"`
	} `json:"data"`
}

// ReadCredential reads the live credential (KVPath).
func (c *Client) ReadCredential(ctx context.Context) (oauth.Credential, error) {
	return c.ReadCredentialAt(ctx, c.KVPath)
}

// WriteCredential writes the live credential (KVPath).
func (c *Client) WriteCredential(ctx context.Context, cred oauth.Credential) error {
	return c.WriteCredentialAt(ctx, c.KVPath, cred)
}

// ReadCredentialAt reads a credential from an arbitrary KV path. A missing
// secret (404) returns ErrNotFound (wrapped).
func (c *Client) ReadCredentialAt(ctx context.Context, path string) (oauth.Credential, error) {
	body, status, err := c.do(ctx, http.MethodGet, c.kvURL("data", path), nil)
	if err != nil {
		return oauth.Credential{}, err
	}
	if status == http.StatusNotFound {
		return oauth.Credential{}, fmt.Errorf("%w at %s (seed refresh token first)", ErrNotFound, path)
	}
	if status != http.StatusOK {
		return oauth.Credential{}, fmt.Errorf("openbao read: status %d: %s", status, string(body))
	}
	var out kvRead
	if err := json.Unmarshal(body, &out); err != nil {
		return oauth.Credential{}, err
	}
	return out.Data.Data, nil
}

// WriteCredentialAt writes a credential to an arbitrary KV path, tagging it with
// this provider's base_url and an updated_at stamp.
func (c *Client) WriteCredentialAt(ctx context.Context, path string, cred oauth.Credential) error {
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
	body, status, err := c.do(ctx, http.MethodPost, c.kvURL("data", path), raw)
	if err != nil {
		return err
	}
	if status != http.StatusOK && status != http.StatusNoContent {
		return fmt.Errorf("openbao write: status %d: %s", status, string(body))
	}
	return nil
}

// DeleteAt removes ALL versions + metadata of a KV path (KV v2 metadata delete),
// used to drop an account permanently. A missing path is treated as success.
func (c *Client) DeleteAt(ctx context.Context, path string) error {
	body, status, err := c.do(ctx, http.MethodDelete, c.kvURL("metadata", path), nil)
	if err != nil {
		return err
	}
	if status != http.StatusOK && status != http.StatusNoContent && status != http.StatusNotFound {
		return fmt.Errorf("openbao delete: status %d: %s", status, string(body))
	}
	return nil
}

// Account is one named credential slot under a provider.
type Account struct {
	ID        string `json:"id"`
	Label     string `json:"label"`
	CreatedMS int64  `json:"created_ms"`
}

// Registry is the per-provider account index stored at Base + /registry: the id
// of the active account (whose credential is mirrored to the live path) plus
// every known account.
type Registry struct {
	Active   string    `json:"active"`
	Accounts []Account `json:"accounts"`
}

// Has reports whether id is a known account.
func (r Registry) Has(id string) bool {
	for _, a := range r.Accounts {
		if a.ID == id {
			return true
		}
	}
	return false
}

// Label returns the account's label, or "" if unknown.
func (r Registry) Label(id string) string {
	for _, a := range r.Accounts {
		if a.ID == id {
			return a.Label
		}
	}
	return ""
}

// Upsert adds an account, or updates an existing account's label (preserving its
// creation time).
func (r *Registry) Upsert(a Account) {
	for i := range r.Accounts {
		if r.Accounts[i].ID == a.ID {
			r.Accounts[i].Label = a.Label
			return
		}
	}
	r.Accounts = append(r.Accounts, a)
}

// Remove drops an account by id.
func (r *Registry) Remove(id string) {
	out := r.Accounts[:0]
	for _, a := range r.Accounts {
		if a.ID != id {
			out = append(out, a)
		}
	}
	r.Accounts = out
}

// ReadRegistry loads the account registry. A registry that was never written
// (404) returns an empty Registry and no error.
func (c *Client) ReadRegistry(ctx context.Context) (Registry, error) {
	body, status, err := c.do(ctx, http.MethodGet, c.kvURL("data", c.registryPath()), nil)
	if err != nil {
		return Registry{}, err
	}
	if status == http.StatusNotFound {
		return Registry{}, nil
	}
	if status != http.StatusOK {
		return Registry{}, fmt.Errorf("openbao registry read: status %d: %s", status, string(body))
	}
	var out struct {
		Data struct {
			Data Registry `json:"data"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return Registry{}, err
	}
	return out.Data.Data, nil
}

// WriteRegistry persists the account registry.
func (c *Client) WriteRegistry(ctx context.Context, reg Registry) error {
	if reg.Accounts == nil {
		reg.Accounts = []Account{}
	}
	raw, _ := json.Marshal(map[string]any{"data": reg})
	body, status, err := c.do(ctx, http.MethodPost, c.kvURL("data", c.registryPath()), raw)
	if err != nil {
		return err
	}
	if status != http.StatusOK && status != http.StatusNoContent {
		return fmt.Errorf("openbao registry write: status %d: %s", status, string(body))
	}
	return nil
}
