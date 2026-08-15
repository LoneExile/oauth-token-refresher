package web

import (
	"context"
	"errors"
	"log/slog"
	"sort"
	"time"

	"github.com/LoneExile/oauth-token-refresher/internal/oauth"
	"github.com/LoneExile/oauth-token-refresher/internal/openbao"
)

// AutoSwitchPolicy decides when the active account is spent and which account
// should take over. Zero Providers = disabled (the opt-in default).
type AutoSwitchPolicy struct {
	// Providers is the set of provider names to manage. Empty disables it.
	Providers []string
	// TriggerPct is the utilization at or above which the active account is
	// considered spent and a switch is considered.
	TriggerPct int
	// MarginPct is how much LESS used a candidate must be before it is worth
	// switching to. It is the anti-flap term: without it, three accounts all
	// sitting near the trigger would hand the active role around in circles.
	MarginPct int
	// Cooldown is the minimum time between switches for one provider.
	Cooldown time.Duration
}

// Enabled reports whether the policy manages the named provider.
func (p AutoSwitchPolicy) Enabled(provider string) bool {
	for _, n := range p.Providers {
		if n == provider {
			return true
		}
	}
	return false
}

// SwitchAction is what the evaluator did for one provider in one pass.
type SwitchAction string

const (
	// ActionNone: the active account is still under the trigger.
	ActionNone SwitchAction = "none"
	// ActionSwitched: the active role moved to an account with more headroom.
	ActionSwitched SwitchAction = "switched"
	// ActionExhausted: the active account is spent and NO other account has
	// enough headroom to be worth taking. This is the state a human has to fix
	// (wait for a window to reset, or add an account), so it is the one the
	// alert is built on.
	ActionExhausted SwitchAction = "exhausted"
	// ActionCooldown: a switch was warranted but one happened too recently.
	ActionCooldown SwitchAction = "cooldown"
	// ActionUnknown: the active account's usage could not be read, so no
	// decision is safe. Deliberately NOT treated as "spent": a probe failure
	// must never cause a switch away from a working account.
	ActionUnknown SwitchAction = "unknown"
)

// SwitchDecision is one provider's outcome, for logging and metrics.
type SwitchDecision struct {
	Provider  string
	Action    SwitchAction
	From      string
	To        string
	FromPct   int
	ToPct     int
	Err       error
	Candidate int // how many accounts were probed as candidates
}

// AutoSwitch evaluates each managed provider and moves the active role to the
// account with the most headroom when the active one is spent.
//
// PROBE COST drives the shape of this. Every usage probe is a real (1-token)
// API call against the provider, so probing every account on every pass would
// be steady-state traffic for a decision that is almost always "do nothing".
// Instead it probes the ACTIVE account only (one call per provider per pass)
// and reaches for the others just when the active one crosses the trigger.
//
// The trigger must fire well before exhaustion: a switch writes OpenBao, and
// consumers only see it after ESO syncs and the kubelet republishes the mounted
// secret, so the new account is perhaps a minute or two away. Switching at 99%
// would hand over an account that is already failing requests.
func (m *Manager) AutoSwitch(ctx context.Context, pol AutoSwitchPolicy, now time.Time) []SwitchDecision {
	if len(pol.Providers) == 0 {
		return nil
	}
	m.accMu.Lock()
	defer m.accMu.Unlock()

	var out []SwitchDecision
	for _, name := range m.order {
		if !pol.Enabled(name) {
			continue
		}
		out = append(out, m.autoSwitchProviderLocked(ctx, m.providers[name], pol, now))
	}
	return out
}

func (m *Manager) autoSwitchProviderLocked(ctx context.Context, p Provider, pol AutoSwitchPolicy, now time.Time) SwitchDecision {
	d := SwitchDecision{Provider: p.Name, Action: ActionNone}
	if p.Prober == nil {
		d.Action = ActionUnknown
		return d
	}
	reg, err := m.ensureRegistryLocked(ctx, p)
	if err != nil {
		d.Action, d.Err = ActionUnknown, err
		return d
	}
	d.From = reg.Active
	if reg.Active == "" || len(reg.Accounts) < 2 {
		// Nothing to switch to. Not an error: a single-account provider is a
		// perfectly normal configuration.
		return d
	}

	activePct, ok := m.probeAccountLocked(ctx, p, reg.Active)
	if !ok {
		d.Action = ActionUnknown
		return d
	}
	d.FromPct = activePct
	if activePct < pol.TriggerPct {
		return d
	}

	// Active is spent — now it is worth spending probes on the alternatives.
	type cand struct {
		id  string
		pct int
	}
	var cands []cand
	for _, a := range reg.Accounts {
		if a.ID == reg.Active {
			continue
		}
		pct, ok := m.probeAccountLocked(ctx, p, a.ID)
		if !ok {
			continue // unknown headroom is not headroom
		}
		d.Candidate++
		if pct <= activePct-pol.MarginPct {
			cands = append(cands, cand{id: a.ID, pct: pct})
		}
	}
	if len(cands) == 0 {
		d.Action = ActionExhausted
		return d
	}
	// Most headroom first; id as a stable tie-break so equal candidates do not
	// depend on map or registry ordering.
	sort.Slice(cands, func(i, j int) bool {
		if cands[i].pct != cands[j].pct {
			return cands[i].pct < cands[j].pct
		}
		return cands[i].id < cands[j].id
	})
	best := cands[0]
	d.To, d.ToPct = best.id, best.pct

	if last, seen := m.lastSwitch[p.Name]; seen && now.Sub(last) < pol.Cooldown {
		d.Action = ActionCooldown
		return d
	}
	if err := m.activateLocked(ctx, p, best.id); err != nil {
		d.Action, d.Err = ActionUnknown, err
		return d
	}
	if m.lastSwitch == nil {
		m.lastSwitch = map[string]time.Time{}
	}
	m.lastSwitch[p.Name] = now
	d.Action = ActionSwitched
	slog.Info("auto-switched active account",
		"provider", p.Name, "from", d.From, "from_pct", d.FromPct,
		"to", d.To, "to_pct", d.ToPct)
	return d
}

// probeAccountLocked reads an account's credential and probes its usage,
// returning the worst window utilization. ok is false when the account has no
// usable token or the probe failed.
func (m *Manager) probeAccountLocked(ctx context.Context, p Provider, id string) (pct int, ok bool) {
	cred, err := p.Bao.ReadCredentialAt(ctx, p.Bao.AccountPath(id))
	if err != nil {
		if !errors.Is(err, openbao.ErrNotFound) {
			slog.Warn("autoswitch: account read failed", "provider", p.Name, "account", id, "err", err)
		}
		return 0, false
	}
	if cred.Access == "" || cred.Expires.Int64() <= 0 || !m.clock().Before(time.UnixMilli(cred.Expires.Int64())) {
		return 0, false // no token, or expired: cannot serve traffic
	}
	probeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return oauth.WorstUtilPercent(p.Prober.ProbeUsage(probeCtx, cred.Access))
}
