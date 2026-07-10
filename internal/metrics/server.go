package metrics

import (
	"encoding/json"
	"net/http"
)

// Register mounts liveness, readiness, JSON status, and Prometheus metrics for
// the given Store on mux. These endpoints are safe to leave open in-cluster
// (Kubernetes probes + Prometheus scraping).
//
//	GET /healthz  liveness (always 200; the loop is self-healing)
//	GET /readyz   readiness (503 until every provider clears its first cycle)
//	GET /status   JSON per-provider status
//	GET /metrics  Prometheus text exposition
func Register(mux *http.ServeMux, store *Store) {
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})

	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		if !store.Ready() {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready\n"))
	})

	mux.HandleFunc("/status", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(store.Snapshot())
	})

	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		store.WritePrometheus(w)
	})
}
