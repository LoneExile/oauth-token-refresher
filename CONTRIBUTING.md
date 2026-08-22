# Contributing

Thanks for wanting to improve oauth-token-refresher! This doc covers the
architecture, how to add a provider, testing, and the build/publish flow.

## Architecture

A single process with three moving parts:

```text
┌──────────────────────── oauth-token-refresher ────────────────────────┐
│  web UI (login + dashboard)  ·  refresh loop (60s)  ·  auto-switch (5m) │
└───────────────┬──────────────────────┬──────────────────────┬──────────┘
                │ OAuth flows           │ refresh_token grants  │ usage probes
                ▼                      ▼                      ▼
        Provider OAuth endpoints   Provider token endpoints   Provider quota APIs
                │                      │                      │
                └──────────┬───────────┘                      │
                           ▼                                  │
                OpenBao KV v2 (accounts, live, registry) ◄────┘
```

- **`cmd/oauth-token-refresher/`** — entrypoint: reads env config, wires
  providers, starts the HTTP server, refresh loop, and auto-switch ticker.
- **`internal/config/`** — env parsing (all `FromEnv`, no config files).
- **`internal/openbao/`** — KV v2 client (read/write/delete credentials,
  registry) and the account `Registry` model.
- **`internal/oauth/`** — provider implementations: login flows (device +
  paste/PKCE), refreshers, and usage probers. Plus the `Credential` type
  (`{access, refresh, expires, base_url}`).
- **`internal/web/`** — the manager (accounts, sessions, auto-switch policy)
  and the server-rendered dashboard.
- **`internal/metrics/`** — Prometheus store.

### Account model

One provider can hold many accounts. The state lives in OpenBao:

| Path | Contents |
|---|---|
| `secret/<provider>/accounts/<id>` | one credential per account, all kept fresh |
| `secret/<provider>/registry` | `{active, accounts[], autoswitch?}` — the index |
| `secret/<provider>/oauth` | **live** credential = the active account, mirrored here for consumers |

Switching accounts copies the chosen credential to the live path and flips
`registry.active` — no re-login, no consumer change.

### Auto-switch policy

`internal/web/autoswitch.go` decides when the active account is spent and
which account takes over:

- **Probing is lazy.** Only the active account is probed each pass (one real
  1-token API call). The others are probed only once the active crosses
  `AUTOSWITCH_TRIGGER_PCT`.
- **Worst-window utilization.** An account's "used" is the highest of its
  windows (Anthropic 5h/7d, xAI subscription quota).
- **Margin + cooldown** prevent flapping between near-equal accounts.
- **Unknown ≠ free.** A failed probe excludes an account from candidacy; a
  failed probe on the active account is never read as "spent".
- **Exhaustion is loud.** When nothing has headroom, the active account is
  left alone and `oauth_refresh_accounts_exhausted` goes to 1.

The per-provider dashboard toggle persists `registry.autoswitch` (`*bool`);
`nil` means "not decided — use the `AUTOSWITCH_PROVIDERS` default". The
evaluator consults it under `accMu` via `autoSwitchEnabledLocked` — never call
the exported `AutoSwitchEnabled` (which takes its own lock) from inside
`AutoSwitch` or you deadlock.

## Adding a provider

1. **`internal/oauth/`** — implement a login flow (device or paste), a
   `Refresher`, and (optionally) a `UsageProber`:
   ```go
   type Refresher interface { Refresh(ctx context.Context, refreshToken string) (Credential, error) }
   type UsageProber interface { ProbeUsage(ctx context.Context, access string) Usage }
   ```
2. **`internal/config/`** — add the `*_ENABLED`, `*_KV_PATH`, `*_BASE_URL`,
   etc. vars.
3. **`cmd/oauth-token-refresher/main.go`** — wire the new type in the provider
   `switch`.
4. **`internal/web/`** — the dashboard renders providers generically; add a
   test that exercises the full add/switch/refresh lifecycle.
5. Document the provider's consumption notes in `README.md`.

## Testing

```bash
go test ./...
go vet ./...
gofmt -l .
```

Tests use an in-memory fake OpenBao KV backend (`internal/web/manager_test.go`,
`fakeVault`) so the whole lifecycle runs without a real vault. Key behaviours
to keep covered:

- lazy probing (active-only below the trigger),
- unknown active account never triggers a switch away,
- dashboard toggle overrides the env default (both directions),
- cooldown and margin anti-flap,
- single-account provider is a no-op.

## Build & publish

- **Docker**: `docker build -t oauth-token-refresher .`
- **CI**: pushes to `main` build and publish to a container registry
  (`.gitlab-ci.yml`). The deployment uses `:latest` with `pullPolicy: Always`,
  so a merge + rollout picks up the new image.
- Version is injected via `-ldflags "-X main.version=<sha>"` and shown in the
  startup log.
