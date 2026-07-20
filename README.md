# oauth-token-refresher

Keeps **provider OAuth access tokens** fresh in **OpenBao** (or HashiCorp Vault) and can
run the initial login for you. Supports **xAI SuperGrok**, **Anthropic (Claude Pro/Max)**,
and **Cline (ClinePass)** out of the box, and can manage them all at once from a single process. Works with any service
that consumes OAuth tokens from a secrets manager.

It can also **log you in**: a built-in web UI (LAN-only) runs each provider's OAuth flow
end-to-end and seeds OpenBao for you — no manual `bao kv put` required.

```text
oauth-token-refresher  →  OpenBao / Vault KV  →  ESO / External Secrets  →  K8s Secret
```

The refresher writes **only** to OpenBao — it does not patch Kubernetes Secrets directly.
Use [External Secrets Operator](https://external-secrets.io/) or any Vault KV consumer to
sync the token into your application Secrets.

## How it works

Mirrors the [OMP OAuth refresh flow](https://omp.sh/docs/memory) for each provider. Every
`LOOP_INTERVAL` (default 60s), for each enabled provider:

1. Read `{access, refresh, expires}` from its OpenBao KV v2 path
2. If access expires within skew (default 10m), exchange the refresh token:
   - **xAI** — OIDC discovery at `XAI_ISSUER`, then an RFC 6749 form-encoded `refresh_token` grant
   - **Anthropic** — a JSON `refresh_token` grant at the fixed `https://api.anthropic.com/v1/oauth/token`, sent with the `anthropic-beta: oauth-2025-04-20` header
   - **Cline (ClinePass)** — a form-encoded `refresh_token` grant at WorkOS `https://api.workos.com/user_management/authenticate`. The response carries no `expires_in`, so the expiry is read from the JWT `exp` claim (~1h). The access token is stored wire-prefixed (`workos:<jwt>`) for `api.cline.bot`.
3. Write the new pair (access + optional rotated refresh + `base_url`) back to OpenBao
4. ESO / your consumer picks up the new value on the next sync interval

Tokens are written with a 5-minute client skew (matching OMP's `ACCESS_TOKEN_CLIENT_SKEW`)
so consumers almost never see a near-dead token. Each successful/failed cycle is recorded
per provider and exposed at `/metrics` and `/status`.

## Self-service login (web UI)

Set `LOGIN_UI_ENABLED=true` (default on) and open the service in a browser to log in to each
provider — the UI runs the full OAuth flow and writes the credential to OpenBao, then the
refresh loop keeps it alive. No manual seeding required.

| Provider | Login flow | What you do |
|---|---|---|
| xAI | Device authorization (RFC 8628) | Click **Log in**, open the shown verification link, confirm the `user_code`, approve. The page polls and completes automatically. |
| Anthropic | Authorization code + PKCE (out-of-band paste) | Click **Log in**, open the authorize link, approve, then paste the returned code back into the form. |
| Cline (ClinePass) | Device authorization (RFC 8628, via WorkOS) | Click **Log in**, open the shown verification link, confirm the `user_code`, approve. The page polls and completes automatically. |

Endpoints: `GET /` (dashboard), `POST /login/{provider}`, `GET /session/{id}`, `POST /session/{id}/code`.

> **Security — gate this.** The login UI mints provider tokens and writes them to OpenBao.
> Expose `/`, `/login/*`, and `/session/*` **LAN-only and behind SSO** (e.g. an auth proxy such as oauth2-proxy). Leave
> `/healthz`, `/readyz`, `/status`, and `/metrics` reachable in-cluster — Kubernetes probes and
> Prometheus scrape the pod directly, bypassing the gateway, so gating the UI does not break
> monitoring. Disable the UI entirely with `LOGIN_UI_ENABLED=false`. Runs single-replica
> (login sessions are in memory).

## Providers

| Provider | Enable | KV path (default) | base_url (default) | Client ID |
|---|---|---|---|---|
| xAI SuperGrok | `XAI_ENABLED=true` *(default on)* | `secret/xai/oauth` | `https://api.x.ai/v1` | `b1a00492-…` (SuperGrok) |
| Anthropic (Claude Pro/Max) | `ANTHROPIC_ENABLED=true` *(opt-in)* | `secret/anthropic/oauth` | `https://api.anthropic.com` | `9d1c250a-…` (Claude Code) |
| Cline (ClinePass) | `CLINE_ENABLED=true` *(opt-in)* | `secret/cline/oauth` | `https://api.cline.bot/api/v1` | `client_01K3A541…` (WorkOS) |

xAI stays enabled by default so existing deployments are unaffected. Enable Anthropic (or
both) by setting the flags below.

> **Anthropic consumption note:** the Anthropic OAuth access token is a **Bearer** token for
> the **native** Anthropic API tied to a Claude Pro/Max subscription — not an API-key. Your
> consumer must send `Authorization: Bearer <access>` **and** the header
> `anthropic-beta: oauth-2025-04-20`. It is not an OpenAI-compatible `/v1` endpoint.

> **Cline consumption note:** the Cline OAuth access token is a **WorkOS JWT** stored
> wire-prefixed as `workos:<jwt>`. The `api.cline.bot` OpenAI-compatible gateway accepts it
> as `Authorization: Bearer workos:<jwt>` (the prefix distinguishes it from an `sk_` API key).
> It rotates ~hourly, so consumers should read it per-request (e.g. a mounted-file/callback)
> rather than pinning it at process start. Subscription-covered `cline-pass/<model>` ids bill
> at cost 0.

## Quick start

### Docker

```bash
docker build -t oauth-token-refresher .
docker run -d --name oauth-token-refresher \
  -e OPENBAO_ADDR=http://your-vault:8200 \
  -e OPENBAO_TOKEN=s.your-token \
  -e ANTHROPIC_ENABLED=true \
  -p 8080:8080 \
  oauth-token-refresher
```

### Seed OpenBao manually (optional)

Prefer the [web UI](#self-service-login-web-ui). To seed by hand instead — or to script it —
put the credential from an OAuth login into the KV path for each provider:

**xAI** — via OMP `/login xai-oauth` (or any OAuth flow):

```bash
bao kv put secret/xai/oauth \
  access="$ACCESS_TOKEN" refresh="$REFRESH_TOKEN" \
  expires="$EXPIRES_MS" base_url="https://api.x.ai/v1"
```

**Anthropic** — via OMP `/login anthropic` (Claude Pro/Max), then copy the credential:

```bash
bao kv put secret/anthropic/oauth \
  access="$ACCESS_TOKEN" refresh="$REFRESH_TOKEN" \
  expires="$EXPIRES_MS" base_url="https://api.anthropic.com"
```

- `expires`: unix **milliseconds** (number)
- `base_url`: the API endpoint your consumer will call
- If a refresh token is ever revoked, re-login and re-seed — no config changes needed

### OpenBao / Vault policy

```hcl
path "secret/data/xai/*"          { capabilities = ["create", "read", "update"] }
path "secret/metadata/xai/*"      { capabilities = ["read", "list", "delete"] }
path "secret/data/anthropic/*"    { capabilities = ["create", "read", "update"] }
path "secret/metadata/anthropic/*"{ capabilities = ["read", "list", "delete"] }
```

Create a periodic service token so it never expires (renew separately):

```bash
bao token create -policy=oauth-refresh -period=768h -orphan
```

## Configuration

All config is env-based — no config files.

### Shared

| Variable | Default | Description |
|---|---|---|
| `OPENBAO_ADDR` | `http://localhost:8200` | OpenBao / Vault API URL |
| `OPENBAO_TOKEN` | *(required)* | Token with R/W on the KV paths |
| `REFRESH_SKEW` | `10m` | Re-mint if expiry ≤ now + skew |
| `LOOP_INTERVAL` | `60s` | Check interval |
| `ONCE` | `false` | Run a single cycle and exit (CronJob mode; exits non-zero on failure) |
| `LISTEN_ADDR` | `:8080` | Health / metrics HTTP listener |
| `LOGIN_UI_ENABLED` | `true` | Serve the self-service login web UI (gate it — see above) |

### xAI provider

| Variable | Default | Description |
|---|---|---|
| `XAI_ENABLED` | `true` | Manage the xAI credential |
| `XAI_KV_PATH` | `secret/xai/oauth` | KV v2 path (falls back to legacy `OPENBAO_KV_PATH`) |
| `XAI_BASE_URL` | `https://api.x.ai/v1` | Written to KV as `base_url` (falls back to legacy `BASE_URL`) |
| `XAI_ISSUER` | `https://auth.x.ai` | OIDC issuer for token-endpoint discovery |
| `XAI_CLIENT_ID` | `b1a00492-073a-47ea-816f-4c329264a828` | SuperGrok OAuth client ID |
| `XAI_SCOPE` | `openid profile email offline_access grok-cli:access api:access` | OAuth scope requested at device login |

### Anthropic provider

| Variable | Default | Description |
|---|---|---|
| `ANTHROPIC_ENABLED` | `false` | Manage the Anthropic credential |
| `ANTHROPIC_KV_PATH` | `secret/anthropic/oauth` | KV v2 path |
| `ANTHROPIC_BASE_URL` | `https://api.anthropic.com` | Written to KV as `base_url` |
| `ANTHROPIC_CLIENT_ID` | `9d1c250a-e61b-44d9-88ed-5944d1962f5e` | Claude Pro/Max OAuth client ID |
| `ANTHROPIC_TOKEN_URL` | `https://api.anthropic.com/v1/oauth/token` | OAuth token endpoint |
| `ANTHROPIC_REDIRECT_URI` | `http://localhost:54545/callback` | Registered redirect URI sent during paste login |

> Legacy `OPENBAO_KV_PATH` and `BASE_URL` are still honored as aliases for the xAI provider,
> so existing deployments keep working without changes.

## Health & metrics endpoints

| Endpoint | Purpose |
|---|---|
| `GET /healthz` | Liveness (always 200) |
| `GET /readyz` | Readiness (503 until every provider clears its first cycle) |
| `GET /status` | JSON: per-provider `last_ok`, `last_error`, `last_refresh`, `access_expiry`, `cycles`, `errors`, `healthy`, `token_valid` |
| `GET /metrics` | Prometheus text exposition (see below) |

The four endpoints above are safe to leave open in-cluster. The login UI (`/`, `/login/*`,
`/session/*`) is sensitive — see [Self-service login](#self-service-login-web-ui).

### Prometheus metrics

All families are prefixed `oauth_refresh_` and labeled `{provider="…"}`:

| Metric | Type | Meaning |
|---|---|---|
| `oauth_refresh_cycles_total` | counter | Refresh cycles run |
| `oauth_refresh_errors_total` | counter | Cycles that errored |
| `oauth_refresh_success` | gauge | Last cycle succeeded (1) / failed (0) |
| `oauth_refresh_token_valid` | gauge | Current access token unexpired (1) / not (0) |
| `oauth_refresh_last_success_timestamp_seconds` | gauge | Unix time of last successful cycle |
| `oauth_refresh_last_refresh_timestamp_seconds` | gauge | Unix time the token was last re-minted |
| `oauth_refresh_access_expiry_timestamp_seconds` | gauge | Unix time the access token expires |
| `oauth_refresh_start_timestamp_seconds` | gauge | Process start time (unlabeled) |

Handy Grafana/PromQL expressions:

```promql
# Seconds until a provider's access token expires
oauth_refresh_access_expiry_timestamp_seconds - time()

# Alert: token expired or refresher failing for >10m
oauth_refresh_token_valid == 0
increase(oauth_refresh_errors_total[10m]) > 0
```

Scrape it with a Prometheus pod annotation (metrics share the health port):

```yaml
metadata:
  annotations:
    prometheus.io/scrape: "true"
    prometheus.io/port: "8080"
    prometheus.io/path: "/metrics"
```

…or a `ServiceMonitor` / `PodMonitor` targeting port `8080` path `/metrics`.

## KV entry shape

Stored at `secret/data/<provider>/oauth` (KV v2):

```json
{
  "access": "eyJ0eXAi...",
  "refresh": "rt-...",
  "expires": 1783578852000,
  "base_url": "https://api.anthropic.com",
  "updated_at": "2026-07-09T05:30:54Z"
}
```

## Kubernetes deployment

Run it as a single-replica Deployment that writes to OpenBao. Any Vault KV consumer can then
materialise the credential into an application Secret — for example the
[External Secrets Operator](https://external-secrets.io/):

```yaml
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata:
  name: my-app-llm
spec:
  refreshInterval: 1m
  secretStoreRef:
    name: openbao
    kind: ClusterSecretStore
  target:
    name: my-app-llm
    creationPolicy: Owner
    template:
      data:
        LLM_API_KEY: "{{ .access }}"
        LLM_BASE_URL: "{{ .base_url }}"
  data:
    - secretKey: access
      remoteRef: { key: anthropic/oauth, property: access }   # or xai/oauth
    - secretKey: base_url
      remoteRef: { key: anthropic/oauth, property: base_url }
```

If your app needs a restart when the Secret changes, pair it with a secret reloader, and
renew the OpenBao service token periodically so it never expires.

## Development

```bash
go test ./...
go build -o /tmp/oauth-refresh ./cmd/oauth-token-refresher
```

### Docker build

```bash
docker build -t oauth-token-refresher .
```

## License

MIT — see [LICENSE](LICENSE)
