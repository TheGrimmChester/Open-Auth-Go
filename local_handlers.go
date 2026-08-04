package openauth

import (
	"encoding/json"
	"net/http"
	"strings"
)

// LocalAuthHandlers serves standalone / co-deployed product auth endpoints:
// POST /api/auth/login, GET /api/auth/status, POST|GET /api/auth/logout,
// and POST /api/auth/register when Mode is standalone.
type LocalAuthHandlers struct {
	Mode         Mode
	Local        *LocalIssuer
	Secret       []byte
	IssuerID     string
	AuthRequired bool
	CookieName   string
}

// Register mounts auth routes on mux.
func (h *LocalAuthHandlers) Register(mux *http.ServeMux) {
	if mux == nil || h == nil {
		return
	}
	mux.HandleFunc("/api/auth/login", h.ServeLogin)
	mux.HandleFunc("/api/auth/status", h.ServeStatus)
	mux.HandleFunc("/api/auth/logout", h.ServeLogout)
	if IsStandalone(h.Mode) {
		mux.HandleFunc("/api/auth/register", h.ServeRegister)
	}
}

// ServeLogin handles POST /api/auth/login.
func (h *LocalAuthHandlers) ServeLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !IsStandalone(h.Mode) || h.Local == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"error":   "auth_mode",
			"message": "login is issued by OPA-Hub in co-deployed mode; set AUTH_MODE=standalone for local auth",
			"mode":    string(h.Mode),
		})
		return
	}
	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&creds); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	tok, exp, claims, err := h.Local.Login(creds.Username, creds.Password)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	writeAuthJSON(w, map[string]interface{}{
		"token":      tok,
		"expires_at": exp.Format("2006-01-02T15:04:05Z07:00"),
		"mode":       string(h.Mode),
		"user":       map[string]interface{}{"username": claims.Username, "role": claims.Role},
	})
}

// ServeStatus handles GET /api/auth/status.
func (h *LocalAuthHandlers) ServeStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	out := map[string]interface{}{
		"mode":          string(h.Mode),
		"auth_required": h.AuthRequired,
		"issuer":        h.IssuerID,
		"standalone":    IsStandalone(h.Mode),
	}
	tok := BearerOrCookie(r, h.CookieName)
	if tok != "" {
		if claims, err := ParseUserJWT(tok, h.Secret); err == nil {
			out["authenticated"] = true
			out["user"] = map[string]interface{}{"username": claims.Username, "role": claims.Role}
			writeAuthJSON(w, out)
			return
		}
	}
	out["authenticated"] = false
	writeAuthJSON(w, out)
}

// ServeLogout handles logout (stateless JWT — client drops token/cookie).
func (h *LocalAuthHandlers) ServeLogout(w http.ResponseWriter, r *http.Request) {
	writeAuthJSON(w, map[string]interface{}{"ok": true})
}

// ServeRegister handles POST /api/auth/register (standalone only).
func (h *LocalAuthHandlers) ServeRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if h.Local == nil {
		http.Error(w, "not available", http.StatusServiceUnavailable)
		return
	}
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	body.Username = strings.TrimSpace(body.Username)
	if err := h.Local.Register(body.Username, body.Password, body.Role); err != nil {
		http.Error(w, "conflict or weak credentials", http.StatusConflict)
		return
	}
	role := body.Role
	if role == "" {
		role = "viewer"
	}
	writeAuthJSON(w, map[string]interface{}{
		"ok":   true,
		"user": map[string]interface{}{"username": body.Username, "role": role},
	})
}

func writeAuthJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
