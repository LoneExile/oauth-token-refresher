package web

import (
	"bytes"
	"fmt"
	"html/template"
	"net/http"
)

// Register mounts the login UI + account management on mux:
//
//	GET  /                                    dashboard (providers → accounts)
//	POST /login/{provider}                    add a NEW account (form field: label)
//	POST /account/{provider}/{id}/relogin     re-login an existing account
//	POST /account/{provider}/{id}/activate    make an account the active one
//	POST /account/{provider}/{id}/remove      delete an account
//	POST /autoswitch/{provider}/on|off        set the provider's auto-switch preference
//	GET  /autoswitch/{provider}               current auto-switch state (JSON)
//	GET  /token/{provider}                    live access token for the active account (JSON, LAN-only)
//	GET  /session/{id}                         login progress / paste form
//	POST /session/{id}/code                    submit a pasted authorization code
func Register(mux *http.ServeMux, m *Manager) {
	mux.HandleFunc("GET /{$}", m.handleDashboard)
	mux.HandleFunc("POST /login/{provider}", m.handleStart)
	mux.HandleFunc("POST /account/{provider}/{id}/relogin", m.handleRelogin)
	mux.HandleFunc("POST /account/{provider}/{id}/activate", m.handleActivate)
	mux.HandleFunc("POST /account/{provider}/{id}/remove", m.handleRemove)
	mux.HandleFunc("GET /autoswitch/{provider}", m.handleAutoSwitchStatus)
	mux.HandleFunc("POST /autoswitch/{provider}/on", m.handleAutoSwitchOn)
	mux.HandleFunc("POST /autoswitch/{provider}/off", m.handleAutoSwitchOff)
	mux.HandleFunc("GET /token/{provider}", m.handleToken)
	mux.HandleFunc("GET /session/{id}", m.handleSession)
	mux.HandleFunc("POST /session/{id}/code", m.handleCode)
}

func (m *Manager) handleDashboard(w http.ResponseWriter, _ *http.Request) {
	render(w, "dashboard", m.Providers(), 0)
}

func (m *Manager) handleStart(w http.ResponseWriter, r *http.Request) {
	sess, err := m.StartLogin(r.PathValue("provider"), "", r.FormValue("label"))
	if err != nil {
		renderMessage(w, "Could not start login: "+err.Error(), true, http.StatusBadGateway)
		return
	}
	http.Redirect(w, r, "/session/"+sess.ID, http.StatusSeeOther)
}

func (m *Manager) handleRelogin(w http.ResponseWriter, r *http.Request) {
	sess, err := m.StartLogin(r.PathValue("provider"), r.PathValue("id"), "")
	if err != nil {
		renderMessage(w, "Could not start re-login: "+err.Error(), true, http.StatusBadGateway)
		return
	}
	http.Redirect(w, r, "/session/"+sess.ID, http.StatusSeeOther)
}

func (m *Manager) handleActivate(w http.ResponseWriter, r *http.Request) {
	if err := m.Activate(r.PathValue("provider"), r.PathValue("id")); err != nil {
		renderMessage(w, "Could not switch account: "+err.Error(), true, http.StatusBadGateway)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (m *Manager) handleRemove(w http.ResponseWriter, r *http.Request) {
	if err := m.RemoveAccount(r.PathValue("provider"), r.PathValue("id")); err != nil {
		renderMessage(w, "Could not remove account: "+err.Error(), true, http.StatusBadGateway)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (m *Manager) handleAutoSwitchOn(w http.ResponseWriter, r *http.Request) {
	if err := m.SetAutoSwitch(r.PathValue("provider"), true); err != nil {
		renderMessage(w, "Could not enable auto-switch: "+err.Error(), true, http.StatusBadGateway)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (m *Manager) handleAutoSwitchOff(w http.ResponseWriter, r *http.Request) {
	if err := m.SetAutoSwitch(r.PathValue("provider"), false); err != nil {
		renderMessage(w, "Could not disable auto-switch: "+err.Error(), true, http.StatusBadGateway)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (m *Manager) handleToken(w http.ResponseWriter, r *http.Request) {
	access, err := m.LiveToken(r.PathValue("provider"))
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		_, _ = fmt.Fprintf(w, `{"error":%q}`, err.Error())
		return
	}
	_, _ = fmt.Fprintf(w, `{"access":%q}`, access)
}

func (m *Manager) handleAutoSwitchStatus(w http.ResponseWriter, r *http.Request) {
	enabled, decided := m.AutoSwitchEnabled(r.PathValue("provider"))
	w.Header().Set("Content-Type", "application/json")
	_, _ = fmt.Fprintf(w, `{"enabled":%t,"decided":%t}`, enabled, decided)
}

func (m *Manager) handleSession(w http.ResponseWriter, r *http.Request) {
	sess, ok := m.Session(r.PathValue("id"))
	if !ok {
		renderMessage(w, "Unknown or expired login session.", true, http.StatusNotFound)
		return
	}
	page, refresh := "session_paste", 0
	if sess.Kind == "device" {
		page = "session_device"
		if sess.State == StatePending {
			refresh = 3 // auto-refresh while waiting for device approval
		}
	}
	render(w, page, sess, refresh)
}

func (m *Manager) handleCode(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	// Errors are recorded on the session and shown on the redirected page.
	_ = m.SubmitCode(id, r.FormValue("code"))
	http.Redirect(w, r, "/session/"+id, http.StatusSeeOther)
}

func render(w http.ResponseWriter, page string, data any, refresh int) {
	var body bytes.Buffer
	if err := tmpl.ExecuteTemplate(&body, page, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = tmpl.ExecuteTemplate(w, "layout", layoutData{Body: template.HTML(body.String()), Refresh: refresh})
}

func renderMessage(w http.ResponseWriter, text string, bad bool, status int) {
	var body bytes.Buffer
	_ = tmpl.ExecuteTemplate(&body, "message", struct {
		Text string
		Bad  bool
	}{Text: text, Bad: bad})
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = tmpl.ExecuteTemplate(w, "layout", layoutData{Body: template.HTML(body.String())})
}
