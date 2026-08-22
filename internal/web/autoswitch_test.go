package web

import (
	"context"
	"github.com/LoneExile/oauth-token-refresher/internal/oauth"
	"github.com/LoneExile/oauth-token-refresher/internal/openbao"
	"strconv"
	"testing"
	"time"
)

// fixedProber returns a canned Usage per access token, so a test can give each
// account a different quota picture. It also counts probes, which is how the
// lazy-probing contract is asserted.
type fixedProber struct {
	byToken map[string]oauth.Usage
	probes  int
}

func (p *fixedProber) ProbeUsage(_ context.Context, access string) oauth.Usage {
	p.probes++
	u, ok := p.byToken[access]
	if !ok {
		return oauth.Usage{Err: "no canned usage"}
	}
	return u
}

func util(fivePct, sevenPct int) oauth.Usage {
	f := func(p int) string {
		return strconv.FormatFloat(float64(p)/100, 'f', 4, 64)
	}
	return oauth.Usage{Window5hUtil: f(fivePct), Window7dUtil: f(sevenPct)}
}

// autoSwitchFixture wires a Manager over a fake vault with the given accounts
// (id -> access token), all with far-future expiry, and `active` as active.
func autoSwitchFixture(t *testing.T, prober oauth.UsageProber, active string, ids ...string) (*Manager, *fakeVault) {
	t.Helper()
	v := newFakeVault(t)
	exp := time.Now().Add(time.Hour).UnixMilli()
	var accs []openbao.Account
	for _, id := range ids {
		v.seedCred("anthropic/accounts/"+id, oauth.Credential{
			Access:  "tok-" + id,
			Refresh: "r",
			Expires: oauth.FlexInt64(exp),
		})
		accs = append(accs, openbao.Account{ID: id, Label: id})
	}
	v.seedRegistry("anthropic/registry", openbao.Registry{Active: active, Accounts: accs})
	m := NewManager([]Provider{{
		Name:   "anthropic",
		Bao:    v.client("anthropic/oauth", ""),
		Prober: prober,
	}})
	return m, v
}

func policy() AutoSwitchPolicy {
	return AutoSwitchPolicy{
		Providers:  []string{"anthropic"},
		TriggerPct: 80,
		MarginPct:  15,
		Cooldown:   15 * time.Minute,
	}
}

func TestAutoSwitchBelowTriggerDoesNothing(t *testing.T) {
	p := &fixedProber{byToken: map[string]oauth.Usage{
		"tok-a": util(10, 20), // active, plenty of headroom
		"tok-b": util(1, 1),
	}}
	m, v := autoSwitchFixture(t, p, "a", "a", "b")

	got := m.AutoSwitch(context.Background(), policy(), time.Now())

	if len(got) != 1 || got[0].Action != ActionNone {
		t.Fatalf("want one %q decision, got %+v", ActionNone, got)
	}
	// Lazy probing: only the ACTIVE account should have been probed, because
	// each probe is a real API call.
	if p.probes != 1 {
		t.Errorf("probes = %d, want 1 (active only below trigger)", p.probes)
	}
	if reg, _ := v.registry("anthropic/registry"); reg.Active != "a" {
		t.Errorf("active moved to %q, want it left at \"a\"", reg.Active)
	}
}

func TestAutoSwitchMovesToMostHeadroom(t *testing.T) {
	p := &fixedProber{byToken: map[string]oauth.Usage{
		"tok-a": util(92, 40), // active, spent on the 5h window
		"tok-b": util(60, 30), // better, but not the best
		"tok-c": util(11, 29), // most headroom
	}}
	m, v := autoSwitchFixture(t, p, "a", "a", "b", "c")

	got := m.AutoSwitch(context.Background(), policy(), time.Now())

	if len(got) != 1 || got[0].Action != ActionSwitched {
		t.Fatalf("want %q, got %+v", ActionSwitched, got)
	}
	if got[0].To != "c" {
		t.Errorf("switched to %q, want \"c\" (lowest worst-window)", got[0].To)
	}
	reg, _ := v.registry("anthropic/registry")
	if reg.Active != "c" {
		t.Fatalf("registry active = %q, want \"c\"", reg.Active)
	}
	// The live path must carry c's credential, not just the pointer: that is
	// what ESO/LiteLLM actually read.
	live, ok := v.cred("anthropic/oauth")
	if !ok || live.Access != "tok-c" {
		t.Errorf("live credential = %q, want \"tok-c\"", live.Access)
	}
}

func TestAutoSwitchExhaustedWhenNoHeadroom(t *testing.T) {
	p := &fixedProber{byToken: map[string]oauth.Usage{
		"tok-a": util(95, 40),
		"tok-b": util(90, 88), // spent too
		"tok-c": util(85, 91), // within the margin, not worth taking
	}}
	m, v := autoSwitchFixture(t, p, "a", "a", "b", "c")

	got := m.AutoSwitch(context.Background(), policy(), time.Now())

	if len(got) != 1 || got[0].Action != ActionExhausted {
		t.Fatalf("want %q, got %+v", ActionExhausted, got)
	}
	if reg, _ := v.registry("anthropic/registry"); reg.Active != "a" {
		t.Errorf("active moved to %q on exhaustion, want it left at \"a\"", reg.Active)
	}
}

// A failed probe must never look like free quota — otherwise one flaky account
// becomes the switch target precisely when the provider is struggling.
func TestAutoSwitchIgnoresUnprobableCandidate(t *testing.T) {
	p := &fixedProber{byToken: map[string]oauth.Usage{
		"tok-a": util(95, 40),
		"tok-b": {Err: "429 probing"},
	}}
	m, v := autoSwitchFixture(t, p, "a", "a", "b")

	got := m.AutoSwitch(context.Background(), policy(), time.Now())

	if len(got) != 1 || got[0].Action != ActionExhausted {
		t.Fatalf("want %q (unknown != free), got %+v", ActionExhausted, got)
	}
	if reg, _ := v.registry("anthropic/registry"); reg.Active != "a" {
		t.Errorf("active moved to an unprobable account (%q)", reg.Active)
	}
}

// An unreadable ACTIVE account must not trigger a switch away from it.
func TestAutoSwitchUnknownActiveIsNotSpent(t *testing.T) {
	p := &fixedProber{byToken: map[string]oauth.Usage{
		"tok-a": {Err: "network"},
		"tok-b": util(1, 1),
	}}
	m, v := autoSwitchFixture(t, p, "a", "a", "b")

	got := m.AutoSwitch(context.Background(), policy(), time.Now())

	if len(got) != 1 || got[0].Action != ActionUnknown {
		t.Fatalf("want %q, got %+v", ActionUnknown, got)
	}
	if reg, _ := v.registry("anthropic/registry"); reg.Active != "a" {
		t.Errorf("active moved to %q on an unreadable active, want \"a\"", reg.Active)
	}
}

func TestAutoSwitchCooldownBlocksSecondSwitch(t *testing.T) {
	p := &fixedProber{byToken: map[string]oauth.Usage{
		"tok-a": util(95, 40),
		"tok-b": util(10, 10),
		"tok-c": util(5, 5),
	}}
	m, _ := autoSwitchFixture(t, p, "a", "a", "b", "c")
	pol := policy()
	t0 := time.Now()

	first := m.AutoSwitch(context.Background(), pol, t0)
	if first[0].Action != ActionSwitched {
		t.Fatalf("first pass: want %q, got %+v", ActionSwitched, first)
	}
	// Spend whichever account actually won (the policy takes the MOST headroom,
	// which is "c", not simply the next one in the registry) so the second pass
	// has a genuine reason to switch and cooldown is what stops it.
	p.byToken["tok-"+first[0].To] = util(96, 40)

	got := m.AutoSwitch(context.Background(), pol, t0.Add(time.Minute))
	if got[0].Action != ActionCooldown {
		t.Fatalf("second pass inside cooldown: want %q, got %+v", ActionCooldown, got)
	}

	got = m.AutoSwitch(context.Background(), pol, t0.Add(pol.Cooldown+time.Second))
	if got[0].Action != ActionSwitched {
		t.Fatalf("after cooldown: want %q, got %+v", ActionSwitched, got)
	}
}

// Disabled is the default: an empty provider list must not probe or switch.
func TestAutoSwitchDisabledByDefault(t *testing.T) {
	p := &fixedProber{byToken: map[string]oauth.Usage{"tok-a": util(99, 99), "tok-b": util(1, 1)}}
	m, v := autoSwitchFixture(t, p, "a", "a", "b")

	if got := m.AutoSwitch(context.Background(), AutoSwitchPolicy{}, time.Now()); got != nil {
		t.Fatalf("disabled policy returned decisions: %+v", got)
	}
	if p.probes != 0 {
		t.Errorf("probes = %d, want 0 when disabled", p.probes)
	}
	if reg, _ := v.registry("anthropic/registry"); reg.Active != "a" {
		t.Errorf("disabled policy switched to %q", reg.Active)
	}
}

// A single-account provider has nothing to switch to and must not be probed.
func TestAutoSwitchSingleAccountIsNoop(t *testing.T) {
	p := &fixedProber{byToken: map[string]oauth.Usage{"tok-a": util(99, 99)}}
	m, _ := autoSwitchFixture(t, p, "a", "a")

	got := m.AutoSwitch(context.Background(), policy(), time.Now())
	if len(got) != 1 || got[0].Action != ActionNone {
		t.Fatalf("want %q, got %+v", ActionNone, got)
	}
	if p.probes != 0 {
		t.Errorf("probes = %d, want 0 for a single-account provider", p.probes)
	}
}

// A dashboard toggle-OFF must win over a default that lists the provider.
func TestAutoSwitchRegistryOffOverridesDefaultOn(t *testing.T) {
	p := &fixedProber{byToken: map[string]oauth.Usage{
		"tok-a": util(99, 99),
		"tok-b": util(1, 1),
	}}
	m, _ := autoSwitchFixture(t, p, "a", "a", "b")
	if err := m.SetAutoSwitch("anthropic", false); err != nil {
		t.Fatal(err)
	}

	got := m.AutoSwitch(context.Background(), policy(), time.Now())
	if got != nil {
		t.Fatalf("registry-off policy returned decisions: %+v", got)
	}
	if p.probes != 0 {
		t.Errorf("probes = %d, want 0 when the registry flag is off", p.probes)
	}
}

// A dashboard toggle-ON must work even when the deployment default lists
// nothing (the exact live scenario: AUTOSWITCH_PROVIDERS is empty).
func TestAutoSwitchRegistryOnOverridesDefaultOff(t *testing.T) {
	p := &fixedProber{byToken: map[string]oauth.Usage{
		"tok-a": util(95, 40), // active, spent
		"tok-b": util(10, 10), // headroom
	}}
	m, v := autoSwitchFixture(t, p, "a", "a", "b")
	if err := m.SetAutoSwitch("anthropic", true); err != nil {
		t.Fatal(err)
	}

	got := m.AutoSwitch(context.Background(), AutoSwitchPolicy{}, time.Now())
	if len(got) != 1 || got[0].Action != ActionSwitched {
		t.Fatalf("want %q with a registry-ON flag and empty default, got %+v", ActionSwitched, got)
	}
	if got[0].To != "b" {
		t.Errorf("switched to %q, want \"b\"", got[0].To)
	}
	reg, _ := v.registry("anthropic/registry")
	if reg.Active != "b" {
		t.Fatalf("registry active = %q, want \"b\"", reg.Active)
	}
}
