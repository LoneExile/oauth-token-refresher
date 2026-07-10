package web

import (
	"bytes"
	"html/template"
	"net/http"
)

// Register mounts the login UI on mux:
//
//	GET  /                     dashboard
//	POST /login/{provider}     start a login
//	GET  /session/{id}         login progress / paste form
//	POST /session/{id}/code    submit a pasted authorization code
func Register(mux *http.ServeMux, m *Manager) {
	mux.HandleFunc("GET /{$}", m.handleDashboard)
	mux.HandleFunc("POST /login/{provider}", m.handleStart)
	mux.HandleFunc("GET /session/{id}", m.handleSession)
	mux.HandleFunc("POST /session/{id}/code", m.handleCode)
}

func (m *Manager) handleDashboard(w http.ResponseWriter, _ *http.Request) {
	render(w, "dashboard", m.Providers(), 0)
}

func (m *Manager) handleStart(w http.ResponseWriter, r *http.Request) {
	sess, err := m.StartLogin(r.PathValue("provider"))
	if err != nil {
		renderMessage(w, "Could not start login: "+err.Error(), true, http.StatusBadGateway)
		return
	}
	http.Redirect(w, r, "/session/"+sess.ID, http.StatusSeeOther)
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
