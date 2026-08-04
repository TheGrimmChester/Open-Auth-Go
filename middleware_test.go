package openauth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLoadJWTSecret(t *testing.T) {
	stable := strings.Repeat("a", 32)
	sec, eph, err := LoadJWTSecret(stable, true)
	if err != nil || eph || string(sec) != stable {
		t.Fatalf("stable: eph=%v err=%v", eph, err)
	}
	if _, _, err := LoadJWTSecret(JWTSecretPlaceholder, true); err == nil {
		t.Fatal("expected error when auth required + placeholder")
	}
	sec, eph, err = LoadJWTSecret("", false)
	if err != nil || !eph || len(sec) != 32 {
		t.Fatalf("ephemeral: eph=%v len=%d err=%v", eph, len(sec), err)
	}
}

func TestHasPermission(t *testing.T) {
	if !HasPermission("admin", "viewer") || !HasPermission("editor", "editor") {
		t.Fatal("expected allow")
	}
	if HasPermission("viewer", "admin") {
		t.Fatal("expected deny")
	}
	if !HasPermission("viewer", "") {
		t.Fatal("empty required always ok")
	}
}

func TestBearerOrCookie(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer abc.def")
	if got := BearerOrCookie(r, ""); got != "abc.def" {
		t.Fatalf("bearer=%q", got)
	}
	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	r2.AddCookie(&http.Cookie{Name: CookieName, Value: "cookietok"})
	if got := BearerOrCookie(r2, ""); got != "cookietok" {
		t.Fatalf("cookie=%q", got)
	}
}

func TestApplyUserTenantHeaders(t *testing.T) {
	claims := &UserClaims{Username: "a", Role: "viewer", OrgID: "acme", ProjectID: "prod"}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Organization-ID", "other")
	if err := ApplyUserTenantHeaders(r, claims); err != ErrTenantMismatch {
		t.Fatalf("want mismatch, got %v", err)
	}
	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	r2.Header.Set("X-Organization-ID", "all")
	if err := ApplyUserTenantHeaders(r2, claims); err != nil {
		t.Fatal(err)
	}
	if r2.Header.Get("X-Organization-ID") != "acme" || r2.Header.Get("X-Project-ID") != "prod" {
		t.Fatalf("headers=%v", r2.Header)
	}
}

func TestRequireUserMiddleware(t *testing.T) {
	secret := []byte(strings.Repeat("b", 32))
	tok, err := MintUserJWT(secret, "alice", "editor", "ora-api", 0)
	if err != nil {
		t.Fatal(err)
	}
	cfg := MiddlewareConfig{Secret: secret}
	var sawUser, sawRole string
	h := cfg.RequireUser("viewer", func(w http.ResponseWriter, r *http.Request) {
		sawUser = r.Header.Get("X-User-Username")
		sawRole = r.Header.Get("X-User-Role")
		w.WriteHeader(http.StatusNoContent)
	})
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rr := httptest.NewRecorder()
	h(rr, req)
	if rr.Code != http.StatusNoContent || sawUser != "alice" || sawRole != "editor" {
		t.Fatalf("code=%d user=%s role=%s", rr.Code, sawUser, sawRole)
	}

	req2 := httptest.NewRequest(http.MethodGet, "/x", nil)
	rr2 := httptest.NewRecorder()
	h(rr2, req2)
	if rr2.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rr2.Code)
	}
}

func TestRequireUserOrService(t *testing.T) {
	userSecret := []byte(strings.Repeat("c", 32))
	svcSecret := []byte(strings.Repeat("d", 32))
	svcTok, err := MintServiceJWT(svcSecret, "osa-api", "ora-api", "connectors:read")
	if err != nil {
		t.Fatal(err)
	}
	cfg := MiddlewareConfig{
		Secret:          userSecret,
		ServiceSecret:   svcSecret,
		ServiceAudience: "ora-api",
	}
	var issuer string
	h := cfg.RequireUserOrService("viewer", "connectors:read", func(w http.ResponseWriter, r *http.Request) {
		issuer = r.Header.Get("X-Service-Issuer")
		w.WriteHeader(http.StatusNoContent)
	})
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Authorization", "Bearer "+svcTok)
	rr := httptest.NewRecorder()
	h(rr, req)
	if rr.Code != http.StatusNoContent || issuer != "osa-api" {
		t.Fatalf("code=%d issuer=%s", rr.Code, issuer)
	}
}

func TestLocalAuthHandlersStandalone(t *testing.T) {
	secret := []byte(strings.Repeat("e", 32))
	li := NewLocalIssuer(secret, "osa-api", "admin", "admin")
	h := &LocalAuthHandlers{
		Mode:         ModeStandalone,
		Local:        li,
		Secret:       li.Secret,
		IssuerID:     "osa-api",
		AuthRequired: false,
	}
	mux := http.NewServeMux()
	h.Register(mux)

	body := `{"username":"admin","password":"admin"}`
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(body))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("login status=%d body=%s", rr.Code, rr.Body.String())
	}
	var login map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &login); err != nil {
		t.Fatal(err)
	}
	tok, _ := login["token"].(string)
	if tok == "" {
		t.Fatal("missing token")
	}

	req2 := httptest.NewRequest(http.MethodGet, "/api/auth/status", nil)
	req2.Header.Set("Authorization", "Bearer "+tok)
	rr2 := httptest.NewRecorder()
	mux.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusOK || !strings.Contains(rr2.Body.String(), `"authenticated":true`) {
		t.Fatalf("status=%d body=%s", rr2.Code, rr2.Body.String())
	}
}

func TestLocalAuthHandlersCodeployedLogin(t *testing.T) {
	h := &LocalAuthHandlers{Mode: ModeCodeployed, IssuerID: "opl-api"}
	mux := http.NewServeMux()
	h.Register(mux)
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(`{"username":"a","password":"b"}`))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503, got %d", rr.Code)
	}
}

func TestBootstrapStandalone(t *testing.T) {
	g, err := Bootstrap(BootstrapConfig{
		IssuerID:     "ora-api",
		JWTSecretEnv: strings.Repeat("f", 32),
		AuthModeEnv:  "standalone",
		SeedUsername: "admin",
		SeedPassword: "admin",
	})
	if err != nil || g == nil || !g.IsStandalone() || g.Local == nil {
		t.Fatalf("gate=%+v err=%v", g, err)
	}
	tok, _, _, err := g.Local.Login("admin", "admin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.ParseUser(tok); err != nil {
		t.Fatal(err)
	}
}
