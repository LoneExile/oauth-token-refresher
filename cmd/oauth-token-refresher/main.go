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
	// login flow (web UI). A provider can hold many accounts (see internal/web);
	// the Manager keeps every account fresh and mirrors the active one to the
	// provider's live KV path.
	webProviders := make([]web.Provider, 0, len(cfg.Providers))
	for _, pc := range cfg.Providers {
		bao := openbao.New(cfg.OpenBaoAddr, cfg.OpenBaoToken, pc.KVPath, pc.BaseURL)
		wp := web.Provider{Name: pc.Name, Bao: bao}
		switch pc.Type {
		case "xai":
			xc := oauth.NewXAI(pc.Issuer, pc.ClientID)
			if pc.Scope != "" {
				xc.Scope = pc.Scope
			}
			wp.Device, wp.Refresher = xc, xc
			wp.Prober = oauth.XAIProber{BaseURL: pc.BaseURL}
		case "anthropic":
			ac := oauth.NewAnthropic(pc.TokenURL, pc.ClientID)
			if pc.RedirectURI != "" {
				ac.Redirect = pc.RedirectURI
			}
			wp.Paste, wp.Refresher = ac, ac
			wp.Prober = oauth.AnthropicProber{BaseURL: pc.BaseURL}
		case "cline":
			cc := oauth.NewCline(pc.Issuer, pc.ClientID)
			wp.Device, wp.Refresher = cc, cc
			wp.Prober = oauth.NoOpProber{}
		default:
			slog.Error("unknown provider type", "provider", pc.Name, "type", pc.Type)
			os.Exit(1)
		}
		webProviders = append(webProviders, wp)
	}

	mgr := web.NewManager(webProviders)
	store := metrics.NewStore(names)
	mux := http.NewServeMux()
	metrics.Register(mux, store)
	if cfg.LoginUI {
		web.Register(mux, mgr)
		slog.Warn("login UI enabled — gate it behind SSO (it mints tokens)")
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

	// run executes one refresh cycle across every provider + account, records
	// per-provider active-account state into metrics, and returns how many
	// providers failed their active-account cycle.
	run := func() int {
		failed := 0
		for _, r := range mgr.RefreshAll(ctx, cfg.RefreshSkew) {
			if r.Err != nil {
				slog.Error("cycle", "provider", r.Provider, "err", r.Err)
				store.Err(r.Provider, r.Err)
				failed++
				continue
			}
			store.OK(r.Provider, r.Expiry, r.Refreshed)
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
