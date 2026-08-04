package openauth

import (
	"crypto/rand"
	"fmt"
	"os"
	"strings"
)

// JWTSecretPlaceholder is the known insecure default rejected at load time.
const JWTSecretPlaceholder = "change-this-secret-key-in-production"

// AuthRequiredEnv reports whether OPA_AUTH_REQUIRED enables enforced auth.
func AuthRequiredEnv() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("OPA_AUTH_REQUIRED"))) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// LoadJWTSecret resolves JWT_SECRET for product APIs.
//
// When envSecret is present, not the placeholder, and at least 32 bytes, it is
// returned as a stable secret (ephemeral=false).
// Otherwise, if authRequired is true, an error is returned (do not start with a
// rotating secret under enforced auth). If authRequired is false, a random
// ephemeral secret is generated (tokens reset on process restart).
func LoadJWTSecret(envSecret string, authRequired bool) (secret []byte, ephemeral bool, err error) {
	envSecret = strings.TrimSpace(envSecret)
	if envSecret != "" && envSecret != JWTSecretPlaceholder && len(envSecret) >= 32 {
		return []byte(envSecret), false, nil
	}
	if authRequired {
		return nil, false, fmt.Errorf("OPA_AUTH_REQUIRED is set but JWT_SECRET is missing/placeholder/<32 bytes")
	}
	secret = make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, false, fmt.Errorf("generate ephemeral JWT secret: %w", err)
	}
	return secret, true, nil
}
