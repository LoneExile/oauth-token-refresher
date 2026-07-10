package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/LoneExile/oauth-token-refresher/internal/config"
	"github.com/LoneExile/oauth-token-refresher/internal/metrics"
	"github.com/LoneExile/oauth-token-refresher/internal/oauth"
	"github.com/LoneExile/oauth-token-refresher/internal/openbao"
	"github.com/LoneExile/oauth-token-refresher/internal/web"
)

var version = "dev"

// managed pairs a provider's refresher with its OpenBao KV client.
type managed struct {
	name string
	ref  oauth.Refresher
	bao  *openbao.Client
}

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})))

	cfg, err := config.FromEnv()
	if err != nil {
		slog.Error("config", "err", err)
		os.Exit(1)
	}

	names := make([]string, 0, len(cfg.Providers))
	for _, p := range cfg.Providers {
		names = append(names, p.Name)
	}
	slog.Info("starting",
		"version", version,
		"providers", names,
		"once", cfg.Once,
		"skew", cfg.RefreshSkew.String(),
		"interval", cfg.LoopInterval.String(),
		"login_ui", cfg.LoginUI,
	)

	// Build providers: each concrete client is both a Refresher (loop) and a
	// login flow (web UI).
	providers := make([]managed, 0, len(cfg.Providers))
	webProviders := make([]web.Provider, 0, len(cfg.Providers))
	for _, pc := range cfg.Providers {
		bao := openbao.New(cfg.OpenBaoAddr, cfg.OpenBaoToken, pc.KVPath, pc.BaseURL)
		wp := web.Provider{Name: pc.Name, Bao: bao}
		var ref oauth.Refresher
		switch pc.Type {
		case "xai":
			xc := oauth.NewXAI(pc.Issuer, pc.ClientID)
			if pc.Scope != "" {
				xc.Scope = pc.Scope
			}
			ref, wp.Device = xc, xc
		case "anthropic":
			ac := oauth.NewAnthropic(pc.TokenURL, pc.ClientID)
			if pc.RedirectURI != "" {
				ac.Redirect = pc.RedirectURI
			}
			ref, wp.Paste = ac, ac
		default:
			slog.Error("unknown provider type", "provider", pc.Name, "type", pc.Type)
			os.Exit(1)
		}
		providers = append(providers, managed{name: pc.Name, ref: ref, bao: bao})
		webProviders = append(webProviders, wp)
	}

	store := metrics.NewStore(names)
	mux := http.NewServeMux()
	metrics.Register(mux, store)
	if cfg.LoginUI {
		web.Register(mux, web.NewManager(webProviders))
		slog.Warn("login UI enabled — gate it behind LAN-only ingress + SSO (it mints tokens)")
	}
	go func() {
		srv := &http.Server{Addr: cfg.ListenAddr, Handler: mux}
		slog.Info("http listening", "addr", cfg.ListenAddr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("http server", "err", err)
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// run executes one cycle per provider and returns how many failed.
	run := func() int {
		failed := 0
		for _, m := range providers {
			if err := cycle(ctx, cfg, m, store); err != nil {
				slog.Error("cycle", "provider", m.name, "err", err)
				store.Err(m.name, err)
				failed++
			}
		}
		return failed
	}

	failed := run()
	if cfg.Once {
		if failed > 0 {
			os.Exit(1)
		}
		return
	}

	t := time.NewTicker(cfg.LoopInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			slog.Info("shutdown")
			return
		case <-t.C:
			run()
		}
	}
}

// cycle refreshes one provider's OAuth pair in OpenBao only. Cluster Secrets (if
// any) are materialised by External Secrets Operator or any Vault KV consumer
// from the same path — no direct Kubernetes API writes.
func cycle(ctx context.Context, cfg config.Config, m managed, st *metrics.Store) error {
	cred, err := m.bao.ReadCredential(ctx)
	if err != nil {
		return err
	}

	refreshed := false
	if oauth.NeedsRefresh(cred, cfg.RefreshSkew) {
		slog.Info("refreshing access token", "provider", m.name, "expires_ms", cred.Expires.Int64())
		next, err := m.ref.Refresh(ctx, cred.Refresh)
		if err != nil {
			return err
		}
		if err := m.bao.WriteCredential(ctx, next); err != nil {
			return err
		}
		cred = next
		refreshed = true
		slog.Info("openbao updated", "provider", m.name, "expires_ms", cred.Expires.Int64())
	} else {
		slog.Info("access still fresh", "provider", m.name, "expires_ms", cred.Expires.Int64())
	}

	expiry := time.UnixMilli(cred.Expires.Int64())
	st.OK(m.name, expiry, refreshed)
	return nil
}
