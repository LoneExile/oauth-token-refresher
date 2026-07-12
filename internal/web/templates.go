package web

import "html/template"

var tmpl = template.Must(template.New("web").Parse(pages))

type layoutData struct {
	Body    template.HTML
	Refresh int // seconds; 0 disables the meta-refresh
}

const pages = `
{{define "layout"}}<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
{{if .Refresh}}<meta http-equiv="refresh" content="{{.Refresh}}">{{end}}
<title>OAuth Refresh</title>
<style>
:root { color-scheme: light dark; }
* { box-sizing: border-box; }
body { margin: 0; font: 15px/1.5 -apple-system, system-ui, "Segoe UI", Roboto, sans-serif;
  background: #0f1115; color: #e6e6e6; }
header { padding: 20px 24px; border-bottom: 1px solid #262a33; }
header h1 { margin: 0 0 4px; font-size: 18px; }
.warn { margin: 0; font-size: 12px; color: #f0b429; }
main { max-width: 820px; margin: 0 auto; padding: 24px; }
.card { background: #171a21; border: 1px solid #262a33; border-radius: 10px;
  padding: 16px 18px; margin: 0 0 14px; }
.row { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
.name { font-weight: 600; font-size: 16px; }
.kind { font-size: 12px; color: #8b93a1; margin-left: 8px; font-weight: 400; }
.status { font-size: 13px; }
.ok { color: #34d399; } .bad { color: #f87171; } .muted { color: #8b93a1; }
.btn { display: inline-block; background: #2563eb; color: #fff; border: 0;
  border-radius: 8px; padding: 9px 16px; font-size: 14px; cursor: pointer; text-decoration: none; }
.btn:hover { background: #1d4ed8; }
.btn.secondary { background: #2a2f3a; }
.btn.secondary:hover { background: #343a47; }
.btn.small { padding: 5px 10px; font-size: 12px; }
.btn.danger { background: #7f1d1d; }
.btn.danger:hover { background: #991b1b; }
code, .code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
.usercode { font-size: 30px; letter-spacing: 4px; font-weight: 700; margin: 12px 0;
  padding: 12px; background: #0f1115; border: 1px dashed #3a4150; border-radius: 8px; text-align: center; }
input[type=text] { width: 100%; padding: 10px; border-radius: 8px; border: 1px solid #3a4150;
  background: #0f1115; color: #e6e6e6; font-family: ui-monospace, monospace; }
label { display: block; font-size: 13px; color: #8b93a1; margin: 12px 0 6px; }
a { color: #60a5fa; }
ol { padding-left: 20px; } li { margin: 6px 0; }
.pill { font-size: 11px; padding: 2px 8px; border-radius: 999px; margin-left: 8px; }
.pill.ok { background: #06331f; color: #34d399; } .pill.bad { background: #3a1414; } .pill.pending { background: #33280a; color: #f0b429; }
table.accounts { width: 100%; border-collapse: collapse; margin: 10px 0 4px; }
table.accounts td { padding: 9px 6px; border-top: 1px solid #262a33; vertical-align: middle; }
.acct-name { font-weight: 600; }
.actions { text-align: right; white-space: nowrap; }
.actions form { display: inline-block; margin-left: 6px; }
form.add { display: flex; gap: 8px; margin-top: 12px; }
form.add input { flex: 1; }
</style>
</head><body>
<header>
  <h1>OAuth Refresh &mdash; self-service login</h1>
  <p class="warn">Sensitive: this UI mints provider tokens and writes them to OpenBao. Keep it behind SSO.</p>
</header>
<main>{{.Body}}</main>
</body></html>{{end}}

{{define "dashboard"}}
{{range $p := .}}
<div class="card">
  <div class="row"><div><span class="name">{{$p.Name}}</span><span class="kind">{{$p.Kind}} flow</span></div></div>
  {{if $p.Accounts}}
  <table class="accounts">
    {{range $a := $p.Accounts}}
    <tr>
      <td class="acct-name">{{$a.Label}}{{if $a.Active}}<span class="pill ok">active</span>{{end}}</td>
      <td class="status">
        {{if $a.Err}}<span class="bad">{{$a.Err}}</span>
        {{else if not $a.Seeded}}<span class="muted">not logged in</span>
        {{else if $a.TokenValid}}
          <span class="ok">&#9679; valid</span> <span class="muted">until {{$a.Expiry.UTC.Format "2006-01-02 15:04 UTC"}}</span><br>
          {{if $a.Usage.Err}}<span class="bad">&#9888; {{$a.Usage.Err}}</span>
          {{else if $a.Usage.TokensRemaining}}<span class="muted">tokens: {{$a.Usage.TokensRemaining}} / {{$a.Usage.TokensLimit}} remaining</span>
          {{else if $a.Usage.RequestsRemaining}}<span class="muted">requests: {{$a.Usage.RequestsRemaining}} / {{$a.Usage.RequestsLimit}} remaining</span>
          {{end}}
        {{else}}<span class="bad">&#9679; expired</span>{{end}}
      </td>
      <td class="actions">
        {{if not $a.Active}}<form method="post" action="/account/{{$p.Name}}/{{$a.ID}}/activate"><button class="btn small" type="submit">Switch to</button></form>{{end}}
        <form method="post" action="/account/{{$p.Name}}/{{$a.ID}}/relogin"><button class="btn small secondary" type="submit">Re-login</button></form>
        <form method="post" action="/account/{{$p.Name}}/{{$a.ID}}/remove" onsubmit="return confirm('Remove account {{$a.Label}}?')"><button class="btn small danger" type="submit">Remove</button></form>
      </td>
    </tr>
    {{end}}
  </table>
  {{else}}
  <p class="muted">No accounts yet &mdash; add one below.</p>
  {{end}}
  <form class="add" method="post" action="/login/{{$p.Name}}">
    <input type="text" name="label" placeholder="Account label (e.g. alice)" autocomplete="off" spellcheck="false">
    <button class="btn" type="submit">Add account</button>
  </form>
</div>
{{else}}
<div class="card"><p class="muted">No login-capable providers are enabled.</p></div>
{{end}}
{{end}}

{{define "session_device"}}
<div class="card">
  <div class="name">{{.Provider}} &mdash; {{.AccountLabel}} <span class="kind">device login</span></div>
  {{if eq (printf "%s" .State) "authorized"}}
    <p class="ok">&#10004; Logged in. The credential was written to OpenBao and will be kept fresh automatically.</p>
    <a class="btn" href="/">Back to dashboard</a>
  {{else if eq (printf "%s" .State) "pending"}}
    <p>1. Open the verification page and confirm the code below:</p>
    <div class="usercode code">{{.UserCode}}</div>
    <p><a class="btn" href="{{.VerificationURI}}" target="_blank" rel="noreferrer noopener">Open verification page</a></p>
    <p class="muted">Waiting for approval&hellip; this page refreshes automatically.</p>
  {{else}}
    <p class="bad">Login {{.State}}: {{.Message}}</p>
    <a class="btn secondary" href="/">Back to dashboard</a>
  {{end}}
</div>
{{end}}

{{define "session_paste"}}
<div class="card">
  <div class="name">{{.Provider}} &mdash; {{.AccountLabel}} <span class="kind">browser login</span></div>
  {{if eq (printf "%s" .State) "authorized"}}
    <p class="ok">&#10004; Logged in. The credential was written to OpenBao and will be kept fresh automatically.</p>
    <a class="btn" href="/">Back to dashboard</a>
  {{else}}
    {{if eq (printf "%s" .State) "error"}}<p class="bad">Previous attempt failed: {{.Message}}</p>{{end}}
    <ol>
      <li><a class="btn" href="{{.AuthURL}}" target="_blank" rel="noreferrer noopener">Open the authorization page</a></li>
      <li>Approve access, then copy the authorization code shown by the provider.</li>
    </ol>
    <form method="post" action="/session/{{.ID}}/code">
      <label for="code">Paste the authorization code (or the full redirect URL / <span class="code">code#state</span>)</label>
      <input id="code" name="code" type="text" autocomplete="off" spellcheck="false" placeholder="paste here" required>
      <p style="margin-top:12px"><button class="btn" type="submit">Complete login</button>
      <a class="btn secondary" href="/">Cancel</a></p>
    </form>
  {{end}}
</div>
{{end}}

{{define "message"}}
<div class="card">
  <p class="{{if .Bad}}bad{{else}}muted{{end}}">{{.Text}}</p>
  <a class="btn secondary" href="/">Back to dashboard</a>
</div>
{{end}}
`
