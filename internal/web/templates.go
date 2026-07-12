package web

import (
	"fmt"
	"html/template"
)

var tmpl = template.Must(template.New("web").Funcs(template.FuncMap{
	"utilPct":   utilPct,
	"utilColor": utilColor,
	"utilBar":   utilBar,
}).Parse(pages))

type layoutData struct {
	Body    template.HTML
	Refresh int // seconds; 0 disables the meta-refresh
}

// utilPct converts a "0.99" string to "99".
func utilPct(s string) string {
	if s == "" {
		return ""
	}
	var f float64
	if _, err := fmt.Sscanf(s, "%f", &f); err != nil {
		return ""
	}
	return fmt.Sprintf("%.0f", f*100)
}

// utilColor returns a CSS color class based on utilization percentage.
func utilColor(s string) string {
	if s == "" {
		return "muted"
	}
	var f float64
	if _, err := fmt.Sscanf(s, "%f", &f); err != nil {
		return "muted"
	}
	switch {
	case f >= 0.9:
		return "quota-crit"
	case f >= 0.75:
		return "quota-warn"
	case f >= 0.4:
		return "quota-mid"
	default:
		return "quota-ok"
	}
}

// utilBar returns the width percentage for a utilization bar.
func utilBar(s string) string {
	if s == "" {
		return "0"
	}
	var f float64
	if _, err := fmt.Sscanf(s, "%f", &f); err != nil {
		return "0"
	}
	pct := f * 100
	if pct > 100 {
		pct = 100
	}
	return fmt.Sprintf("%.0f", pct)
}

const pages = `
{{define "layout"}}<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
{{if .Refresh}}<meta http-equiv="refresh" content="{{.Refresh}}">{{end}}
<title>OAuth Refresh</title>
<style>
:root {
  color-scheme: dark;
  --bg: oklch(0.17 0.008 250);
  --surface: oklch(0.21 0.010 250);
  --surface-hi: oklch(0.25 0.012 250);
  --border: oklch(0.30 0.010 250);
  --text: oklch(0.90 0.005 250);
  --text-dim: oklch(0.62 0.008 250);
  --text-faint: oklch(0.48 0.006 250);
  --accent: oklch(0.62 0.19 255);
  --accent-hi: oklch(0.56 0.22 255);
  --green: oklch(0.72 0.17 155);
  --amber: oklch(0.75 0.15 85);
  --red: oklch(0.65 0.20 25);
  --bar-bg: oklch(0.14 0.006 250);
}
* { box-sizing: border-box; margin: 0; }
body {
  font: 14px/1.6 -apple-system, system-ui, "Segoe UI", Roboto, sans-serif;
  background: var(--bg); color: var(--text);
  display: flex; flex-direction: column; min-height: 100vh;
}
header {
  padding: 18px 28px; border-bottom: 1px solid var(--border);
  display: flex; align-items: baseline; gap: 16px; flex-wrap: wrap;
}
header h1 { font-size: 16px; font-weight: 600; letter-spacing: -0.01em; }
.warn { font-size: 12px; color: var(--amber); }
main { flex: 1; max-width: 720px; width: 100%; margin: 0 auto; padding: 28px 24px 48px; }

.provider { margin-bottom: 28px; }
.provider-head {
  display: flex; align-items: baseline; gap: 8px; margin-bottom: 8px; padding: 0 4px;
}
.provider-name { font-size: 15px; font-weight: 600; letter-spacing: 0.02em; text-transform: uppercase; color: var(--text-dim); }
.provider-kind { font-size: 12px; color: var(--text-faint); }

.acct {
  background: var(--surface); border: 1px solid var(--border);
  border-radius: 8px; padding: 14px 16px; margin-bottom: 8px;
  display: flex; align-items: center; gap: 14px;
}
.acct.active { border-color: oklch(0.40 0.10 155); background: oklch(0.22 0.015 155); }

.acct-info { flex: 1; min-width: 0; }
.acct-label { font-size: 14px; font-weight: 600; margin-bottom: 2px; }
.acct-badge {
  display: inline-block; font-size: 10px; font-weight: 600; letter-spacing: 0.04em;
  text-transform: uppercase; padding: 1px 7px; border-radius: 999px;
  margin-left: 6px; vertical-align: 1px;
}
.acct-badge.active { background: oklch(0.30 0.08 155); color: var(--green); }

.token-status { font-size: 12px; margin-bottom: 6px; }
.token-status .ok { color: var(--green); }
.token-status .bad { color: var(--red); }
.token-status .muted { color: var(--text-faint); }
.token-status .dot { font-size: 8px; vertical-align: 2px; }

.quota { margin-top: 4px; }
.quota-row { display: flex; align-items: center; gap: 8px; margin-bottom: 3px; }
.quota-label { font-size: 11px; color: var(--text-faint); width: 32px; flex-shrink: 0; text-transform: uppercase; letter-spacing: 0.03em; }
.quota-bar { flex: 1; height: 4px; background: var(--bar-bg); border-radius: 2px; overflow: hidden; }
.quota-fill { height: 100%; border-radius: 2px; transition: width 0.3s ease; }
.quota-ok { background: var(--green); }
.quota-mid { background: var(--amber); }
.quota-warn { background: oklch(0.70 0.16 60); }
.quota-crit { background: var(--red); }
.quota-pct { font-size: 11px; width: 34px; text-align: right; flex-shrink: 0; font-variant-numeric: tabular-nums; }
.quota-crit-text { color: var(--red); }
.quota-warn-text { color: oklch(0.72 0.14 60); }
.quota-ok-text { color: var(--text-faint); }
.quota-err { font-size: 12px; color: var(--red); margin-top: 2px; }
.quota-status { font-size: 11px; color: var(--amber); margin-top: 2px; text-transform: uppercase; letter-spacing: 0.03em; }

.acct-actions { display: flex; flex-direction: column; gap: 4px; flex-shrink: 0; }
.btn {
  display: inline-block; border: 0; border-radius: 6px; padding: 6px 12px;
  font-size: 12px; font-weight: 500; cursor: pointer; text-decoration: none;
  text-align: center; white-space: nowrap;
}
.btn-primary { background: var(--accent); color: oklch(0.98 0.005 250); }
.btn-primary:hover { background: var(--accent-hi); }
.btn-secondary { background: var(--surface-hi); color: var(--text-dim); }
.btn-secondary:hover { background: oklch(0.30 0.010 250); color: var(--text); }
.btn-danger { background: oklch(0.25 0.04 25); color: oklch(0.70 0.12 25); }
.btn-danger:hover { background: oklch(0.30 0.06 25); color: oklch(0.85 0.10 25); }

.add-acct { display: flex; gap: 6px; margin-top: 8px; padding: 0 4px; }
.add-acct input {
  flex: 1; padding: 8px 10px; border-radius: 6px; border: 1px solid var(--border);
  background: var(--surface); color: var(--text); font: inherit; font-size: 13px;
}
.add-acct input::placeholder { color: var(--text-faint); }
.add-acct .btn { padding: 8px 14px; }

code, .code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
.usercode { font-size: 28px; letter-spacing: 4px; font-weight: 700; margin: 12px 0;
  padding: 14px; background: var(--bg); border: 1px dashed var(--border); border-radius: 8px; text-align: center; }
input[type=text] {
  width: 100%; padding: 10px; border-radius: 8px; border: 1px solid var(--border);
  background: var(--bg); color: var(--text); font-family: ui-monospace, monospace;
}
label { display: block; font-size: 13px; color: var(--text-dim); margin: 12px 0 6px; }
a { color: oklch(0.68 0.12 255); }
ol { padding-left: 20px; } li { margin: 6px 0; }

.session-card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 20px; }
.session-head { font-size: 15px; font-weight: 600; margin-bottom: 12px; }
.session-head .kind { font-size: 12px; color: var(--text-faint); font-weight: 400; margin-left: 8px; }
.msg { padding: 14px 16px; background: var(--surface); border: 1px solid var(--border); border-radius: 8px; }
.msg p { font-size: 14px; }
.msg .muted { color: var(--text-dim); }
.msg .bad { color: var(--red); }
</style>
</head><body>
<header>
  <h1>OAuth Refresh</h1>
  <span class="warn">Sensitive: mints provider tokens, writes to OpenBao. Keep behind SSO.</span>
</header>
<main>{{.Body}}</main>
</body></html>{{end}}

{{define "dashboard"}}
{{range $p := .}}
<div class="provider">
  <div class="provider-head">
    <span class="provider-name">{{$p.Name}}</span>
    <span class="provider-kind">{{$p.Kind}} flow</span>
  </div>
  {{if $p.Accounts}}
    {{range $a := $p.Accounts}}
    <div class="acct{{if $a.Active}} active{{end}}">
      <div class="acct-info">
        <div class="acct-label">{{$a.Label}}{{if $a.Active}}<span class="acct-badge active">active</span>{{end}}</div>
        <div class="token-status">
          {{if $a.Err}}<span class="bad">{{$a.Err}}</span>
          {{else if not $a.Seeded}}<span class="muted">not logged in</span>
          {{else if $a.TokenValid}}
            <span class="ok">&#9679;</span> <span class="muted">valid until {{$a.Expiry.UTC.Format "Jan 02 15:04 UTC"}}</span>
          {{else}}<span class="bad">&#9679; expired</span>{{end}}
        </div>
        {{if $a.TokenValid}}
        <div class="quota">
          {{if $a.Usage.Err}}
            <div class="quota-err">&#9888; {{$a.Usage.Err}}</div>
          {{else if $a.Usage.Window7dUtil}}
            <div class="quota-row">
              <span class="quota-label">7d</span>
              <div class="quota-bar"><div class="quota-fill {{utilColor $a.Usage.Window7dUtil}}" style="width: {{utilBar $a.Usage.Window7dUtil}}%"></div></div>
              <span class="quota-pct {{utilColor $a.Usage.Window7dUtil}}-text">{{utilPct $a.Usage.Window7dUtil}}%</span>
            </div>
            {{if $a.Usage.Window5hUtil}}
            <div class="quota-row">
              <span class="quota-label">5h</span>
              <div class="quota-bar"><div class="quota-fill {{utilColor $a.Usage.Window5hUtil}}" style="width: {{utilBar $a.Usage.Window5hUtil}}%"></div></div>
              <span class="quota-pct {{utilColor $a.Usage.Window5hUtil}}-text">{{utilPct $a.Usage.Window5hUtil}}%</span>
            </div>
            {{end}}
            {{if eq $a.Usage.Status "allowed_warning"}}<div class="quota-status">&#9888; warning</div>{{end}}
            {{if eq $a.Usage.Status "blocked"}}<div class="quota-status">&#9888; blocked</div>{{end}}
          {{else if $a.Usage.TokensRemaining}}
            <div class="quota-row">
              <span class="quota-label">tok</span>
              <div class="quota-bar"><div class="quota-fill quota-ok" style="width: 100%"></div></div>
              <span class="quota-pct quota-ok-text">{{$a.Usage.TokensRemaining}}/{{$a.Usage.TokensLimit}}</span>
            </div>
          {{else if $a.Usage.RequestsRemaining}}
            <div class="quota-row">
              <span class="quota-label">req</span>
              <div class="quota-bar"><div class="quota-fill quota-ok" style="width: 100%"></div></div>
              <span class="quota-pct quota-ok-text">{{$a.Usage.RequestsRemaining}}/{{$a.Usage.RequestsLimit}}</span>
            </div>
          {{end}}
        </div>
        {{end}}
      </div>
      <div class="acct-actions">
        {{if not $a.Active}}<form method="post" action="/account/{{$p.Name}}/{{$a.ID}}/activate"><button class="btn btn-primary" type="submit">Switch to</button></form>{{end}}
        <form method="post" action="/account/{{$p.Name}}/{{$a.ID}}/relogin"><button class="btn btn-secondary" type="submit">Re-login</button></form>
        <form method="post" action="/account/{{$p.Name}}/{{$a.ID}}/remove" onsubmit="return confirm('Remove account {{$a.Label}}?')"><button class="btn btn-danger" type="submit">Remove</button></form>
      </div>
    </div>
    {{end}}
  {{else}}
    <div style="padding: 12px 4px; font-size: 13px; color: var(--text-faint)">No accounts. Add one below.</div>
  {{end}}
  <form class="add-acct" method="post" action="/login/{{$p.Name}}">
    <input type="text" name="label" placeholder="Account label (e.g. alice)" autocomplete="off" spellcheck="false">
    <button class="btn btn-secondary" type="submit">Add account</button>
  </form>
</div>
{{else}}
<div class="msg"><p class="muted">No login-capable providers are enabled.</p></div>
{{end}}
{{end}}

{{define "session_device"}}
<div class="session-card">
  <div class="session-head">{{.Provider}} <span class="kind">{{.AccountLabel}} device login</span></div>
  {{if eq (printf "%s" .State) "authorized"}}
    <p class="ok" style="color: var(--green)">&#10004; Logged in. Credential written to OpenBao, will be kept fresh automatically.</p>
    <p style="margin-top: 12px"><a class="btn btn-primary" href="/">Back to dashboard</a></p>
  {{else if eq (printf "%s" .State) "pending"}}
    <p style="margin-bottom: 8px">1. Open the verification page and confirm the code:</p>
    <div class="usercode code">{{.UserCode}}</div>
    <p><a class="btn btn-primary" href="{{.VerificationURI}}" target="_blank" rel="noreferrer noopener">Open verification page</a></p>
    <p class="muted" style="font-size: 12px; margin-top: 12px">Waiting for approval. This page refreshes automatically.</p>
  {{else}}
    <p class="bad">Login {{.State}}: {{.Message}}</p>
    <p style="margin-top: 12px"><a class="btn btn-secondary" href="/">Back to dashboard</a></p>
  {{end}}
</div>
{{end}}

{{define "session_paste"}}
<div class="session-card">
  <div class="session-head">{{.Provider}} <span class="kind">{{.AccountLabel}} browser login</span></div>
  {{if eq (printf "%s" .State) "authorized"}}
    <p style="color: var(--green)">&#10004; Logged in. Credential written to OpenBao, will be kept fresh automatically.</p>
    <p style="margin-top: 12px"><a class="btn btn-primary" href="/">Back to dashboard</a></p>
  {{else}}
    {{if eq (printf "%s" .State) "error"}}<p class="bad" style="margin-bottom: 12px">Previous attempt failed: {{.Message}}</p>{{end}}
    <ol>
      <li><a class="btn btn-primary" href="{{.AuthURL}}" target="_blank" rel="noreferrer noopener">Open the authorization page</a></li>
      <li>Approve access, then copy the authorization code shown by the provider.</li>
    </ol>
    <form method="post" action="/session/{{.ID}}/code" style="margin-top: 16px">
      <label for="code">Paste the authorization code (or the full redirect URL / <span class="code">code#state</span>)</label>
      <input id="code" name="code" type="text" autocomplete="off" spellcheck="false" placeholder="paste here" required>
      <p style="margin-top: 12px"><button class="btn btn-primary" type="submit">Complete login</button>
      <a class="btn btn-secondary" href="/">Cancel</a></p>
    </form>
  {{end}}
</div>
{{end}}

{{define "message"}}
<div class="msg">
  <p class="{{if .Bad}}bad{{else}}muted{{end}}">{{.Text}}</p>
  <p style="margin-top: 12px"><a class="btn btn-secondary" href="/">Back to dashboard</a></p>
</div>
{{end}}
`
