// Package metrics holds per-provider OAuth refresh state and exposes it as JSON
// status and Prometheus metrics. It is the single source of truth behind the
// /status, /metrics, and readiness endpoints.
package metrics

import (
	"io"
	"strconv"
	"sync"
	"time"
)

type providerState struct {
	lastOK       time.Time
	lastError    string
	lastRefresh  time.Time
	accessExpiry time.Time
	cycles       int64
	errors       int64
	lastSuccess  bool
}

// Store tracks refresh state for every managed provider. Safe for concurrent use.
type Store struct {
	mu    sync.RWMutex
	state map[string]*providerState
	order []string
	start time.Time
}

// NewStore pre-registers the given providers so metric/status output is
// deterministic even before the first cycle runs.
func NewStore(providers []string) *Store {
	s := &Store{state: make(map[string]*providerState, len(providers)), start: time.Now().UTC()}
	for _, p := range providers {
		if _, ok := s.state[p]; ok {
			continue
		}
		s.state[p] = &providerState{}
		s.order = append(s.order, p)
	}
	return s
}

func (s *Store) get(provider string) *providerState {
	ps := s.state[provider]
	if ps == nil {
		ps = &providerState{}
		s.state[provider] = ps
		s.order = append(s.order, provider)
	}
	return ps
}

// OK records a successful cycle for provider, with the current access expiry and
// whether the token was re-minted this cycle.
func (s *Store) OK(provider string, expiry time.Time, refreshed bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ps := s.get(provider)
	now := time.Now().UTC()
	ps.lastOK = now
	ps.lastError = ""
	ps.lastSuccess = true
	ps.accessExpiry = expiry.UTC()
	ps.cycles++
	if refreshed {
		ps.lastRefresh = now
	}
}

// Err records a failed cycle for provider.
func (s *Store) Err(provider string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ps := s.get(provider)
	ps.lastError = err.Error()
	ps.lastSuccess = false
	ps.cycles++
	ps.errors++
}

// ProviderSnapshot is the JSON /status shape for one provider.
type ProviderSnapshot struct {
	LastOK       time.Time `json:"last_ok,omitempty"`
	LastError    string    `json:"last_error,omitempty"`
	LastRefresh  time.Time `json:"last_refresh,omitempty"`
	AccessExpiry time.Time `json:"access_expiry,omitempty"`
	Cycles       int64     `json:"cycles"`
	Errors       int64     `json:"errors"`
	Healthy      bool      `json:"healthy"`
	TokenValid   bool      `json:"token_valid"`
}

// Snapshot returns the current per-provider status, keyed by provider name.
func (s *Store) Snapshot() map[string]ProviderSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := time.Now()
	out := make(map[string]ProviderSnapshot, len(s.order))
	for _, name := range s.order {
		ps := s.state[name]
		out[name] = ProviderSnapshot{
			LastOK:       ps.lastOK,
			LastError:    ps.lastError,
			LastRefresh:  ps.lastRefresh,
			AccessExpiry: ps.accessExpiry,
			Cycles:       ps.cycles,
			Errors:       ps.errors,
			Healthy:      ps.lastError == "" && !ps.lastOK.IsZero(),
			TokenValid:   !ps.accessExpiry.IsZero() && ps.accessExpiry.After(now),
		}
	}
	return out
}

// Ready reports serving readiness. The refresher serves the login UI and
// /metrics regardless of per-provider state, so an unseeded or forbidden
// provider must NOT take the pod out of service — otherwise the very UI used to
// seed it becomes unreachable. Per-provider health is exposed via /status and
// /metrics; answering this call at all means the server is up.
func (s *Store) Ready() bool { return true }

// WritePrometheus renders the state in Prometheus text exposition format
// (version 0.0.4). All metric families are prefixed oauth_refresh_ and labeled
// by provider, so Grafana can chart token health across providers.
func (s *Store) WritePrometheus(w io.Writer) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := time.Now()

	io.WriteString(w, "# HELP oauth_refresh_start_timestamp_seconds Unix time the refresher process started.\n")
	io.WriteString(w, "# TYPE oauth_refresh_start_timestamp_seconds gauge\n")
	io.WriteString(w, "oauth_refresh_start_timestamp_seconds "+itoa(s.start.Unix())+"\n")

	families := []struct {
		name string
		help string
		typ  string
		val  func(*providerState) float64
	}{
		{"oauth_refresh_cycles_total", "Total refresh cycles run per provider.", "counter",
			func(p *providerState) float64 { return float64(p.cycles) }},
		{"oauth_refresh_errors_total", "Total refresh cycles that errored per provider.", "counter",
			func(p *providerState) float64 { return float64(p.errors) }},
		{"oauth_refresh_last_success_timestamp_seconds", "Unix time of the last successful cycle (0 if never).", "gauge",
			func(p *providerState) float64 { return unixOrZero(p.lastOK) }},
		{"oauth_refresh_last_refresh_timestamp_seconds", "Unix time the access token was last re-minted (0 if never).", "gauge",
			func(p *providerState) float64 { return unixOrZero(p.lastRefresh) }},
		{"oauth_refresh_access_expiry_timestamp_seconds", "Unix time the current access token expires (0 if unknown).", "gauge",
			func(p *providerState) float64 { return unixOrZero(p.accessExpiry) }},
		{"oauth_refresh_success", "Whether the last cycle succeeded (1) or failed (0).", "gauge",
			func(p *providerState) float64 { return b2f(p.lastSuccess) }},
		{"oauth_refresh_token_valid", "Whether the current access token is unexpired (1) or not (0).", "gauge",
			func(p *providerState) float64 { return b2f(!p.accessExpiry.IsZero() && p.accessExpiry.After(now)) }},
	}

	for _, f := range families {
		io.WriteString(w, "# HELP "+f.name+" "+f.help+"\n")
		io.WriteString(w, "# TYPE "+f.name+" "+f.typ+"\n")
		for _, name := range s.order {
			ps := s.state[name]
			io.WriteString(w, f.name+`{provider="`+name+`"} `+ftoa(f.val(ps))+"\n")
		}
	}
}

func unixOrZero(t time.Time) float64 {
	if t.IsZero() {
		return 0
	}
	return float64(t.Unix())
}

func b2f(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

func ftoa(f float64) string { return strconv.FormatFloat(f, 'f', -1, 64) }
