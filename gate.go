package openauth

import (
	"log"
	"net/http"
	"os"
	"strings"
)

// Gate is the product-facing auth wiring: secret load, mode, middleware, and
// optional standalone LocalIssuer + HTTP handlers.
type Gate struct {
	Secret            []byte
	Ephemeral         bool
	Mode              Mode
	IssuerID          string
	Local             *LocalIssuer
	AuthRequired      bool
	CookieName        string
	ServiceSecret     []byte
	ServiceAudience   string
	middleware        MiddlewareConfig
	localHandlers     *LocalAuthHandlers
}

// BootstrapConfig configures Gate construction for a product API.
type BootstrapConfig struct {
	IssuerID        string // e.g. "ora-api"
	JWTSecretEnv    string // typically os.Getenv("JWT_SECRET")
	AuthModeEnv     string // typically os.Getenv("AUTH_MODE")
	PeerHubURL      string // typically os.Getenv("PEER_OPA_URL")
	AuthRequired    bool   // AuthRequiredEnv()
	SeedUsername    string // standalone lab admin (default admin)
	SeedPassword    string // standalone lab password (default admin)
	ServiceSecret   string // OPEN_SERVICE_JWT_SECRET
	ServiceAudience string // expected service aud when using RequireUserOrService
	CookieName      string // default CookieName
}

// Bootstrap builds a Gate for a product API. Standalone mode creates a
// LocalIssuer and may adopt its secret (including ephemeral).
func Bootstrap(cfg BootstrapConfig) (*Gate, error) {
	if strings.TrimSpace(cfg.IssuerID) == "" {
		return nil, ErrInvalidToken
	}
	secret, ephemeral, err := LoadJWTSecret(cfg.JWTSecretEnv, cfg.AuthRequired)
	if err != nil {
		return nil, err
	}
	mode := ResolveMode(cfg.AuthModeEnv, cfg.PeerHubURL)
	cookie := cfg.CookieName
	if cookie == "" {
		cookie = CookieName
	}
	g := &Gate{
		Secret:          secret,
		Ephemeral:       ephemeral,
		Mode:            mode,
		IssuerID:        cfg.IssuerID,
		AuthRequired:    cfg.AuthRequired,
		CookieName:      cookie,
		ServiceSecret:   []byte(strings.TrimSpace(cfg.ServiceSecret)),
		ServiceAudience: strings.TrimSpace(cfg.ServiceAudience),
	}
	if ephemeral {
		log.Printf("auth: JWT_SECRET unset/weak — using ephemeral secret (tokens reset on restart)")
	}
	if IsStandalone(mode) {
		g.Local = NewLocalIssuer(secret, cfg.IssuerID, cfg.SeedUsername, cfg.SeedPassword)
		g.Secret = g.Local.Secret
		// LocalIssuer may have generated a secret if input was empty; treat as ephemeral
		// when the original load was ephemeral or env was empty.
		if ephemeral || strings.TrimSpace(cfg.JWTSecretEnv) == "" {
			g.Ephemeral = true
		}
		log.Printf("auth: mode=standalone issuer=%s (local /api/auth/login)", cfg.IssuerID)
	} else {
		log.Printf("auth: mode=codeployed (validate shared JWT_SECRET; hub issues tokens)")
	}
	g.rebuildHelpers()
	return g, nil
}

// BootstrapFromEnv is Bootstrap using standard Open-* environment variables.
func BootstrapFromEnv(issuerID, serviceAudience string) (*Gate, error) {
	seedUser := strings.TrimSpace(os.Getenv("AUTH_ADMIN_USER"))
	seedPass := strings.TrimSpace(os.Getenv("AUTH_ADMIN_PASSWORD"))
	return Bootstrap(BootstrapConfig{
		IssuerID:        issuerID,
		JWTSecretEnv:    os.Getenv("JWT_SECRET"),
		AuthModeEnv:     os.Getenv("AUTH_MODE"),
		PeerHubURL:      os.Getenv("PEER_OPA_URL"),
		AuthRequired:    AuthRequiredEnv(),
		SeedUsername:    seedUser,
		SeedPassword:    seedPass,
		ServiceSecret:   os.Getenv("OPEN_SERVICE_JWT_SECRET"),
		ServiceAudience: serviceAudience,
	})
}

func (g *Gate) rebuildHelpers() {
	if g == nil {
		return
	}
	g.middleware = MiddlewareConfig{
		Secret:          g.Secret,
		CookieName:      g.CookieName,
		ServiceSecret:   g.ServiceSecret,
		ServiceAudience: g.ServiceAudience,
	}
	g.localHandlers = &LocalAuthHandlers{
		Mode:         g.Mode,
		Local:        g.Local,
		Secret:       g.Secret,
		IssuerID:     g.IssuerID,
		AuthRequired: g.AuthRequired,
		CookieName:   g.CookieName,
	}
}

// Middleware returns user-JWT middleware for the required role.
func (g *Gate) Middleware(requiredRole string, next http.HandlerFunc) http.HandlerFunc {
	return g.middleware.RequireUser(requiredRole, next)
}

// UserOrServiceMiddleware returns middleware that accepts user or service JWTs.
func (g *Gate) UserOrServiceMiddleware(requiredRole, requiredServiceScope string, next http.HandlerFunc) http.HandlerFunc {
	return g.middleware.RequireUserOrService(requiredRole, requiredServiceScope, next)
}

// RegisterLocalAuth mounts /api/auth/* handlers.
func (g *Gate) RegisterLocalAuth(mux *http.ServeMux) {
	if g == nil || g.localHandlers == nil {
		return
	}
	g.localHandlers.Register(mux)
}

// ParseUser validates a user JWT against this gate's secret.
func (g *Gate) ParseUser(token string) (*UserClaims, error) {
	if g == nil {
		return nil, ErrInvalidToken
	}
	return ParseUserJWT(token, g.Secret)
}

// IsStandalone reports whether this gate is in standalone mode.
func (g *Gate) IsStandalone() bool {
	return g != nil && IsStandalone(g.Mode)
}
