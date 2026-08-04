package openauth

import (
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const defaultUserTTL = 24 * time.Hour

// MintUserJWT issues a user-facing HS256 JWT with JWT_SECRET.
// issuer should be the product service id (e.g. "ora-api", "opa-hub").
func MintUserJWT(secret []byte, username, role, issuer string, ttl time.Duration) (string, error) {
	return MintUserJWTWithTenant(secret, username, role, issuer, "", "", ttl)
}

// MintUserJWTWithTenant issues a user JWT optionally bound to org_id / project_id.
// When orgID or projectID is non-empty, product middleware should enforce that
// request tenant headers match (or overwrite them from the claims).
func MintUserJWTWithTenant(secret []byte, username, role, issuer, orgID, projectID string, ttl time.Duration) (string, error) {
	username = strings.TrimSpace(username)
	role = strings.TrimSpace(role)
	issuer = strings.TrimSpace(issuer)
	orgID = strings.TrimSpace(orgID)
	projectID = strings.TrimSpace(projectID)
	if len(secret) == 0 || username == "" {
		return "", ErrInvalidToken
	}
	if ttl <= 0 {
		ttl = defaultUserTTL
	}
	now := time.Now().UTC()
	if role == "" {
		role = "viewer"
	}
	claims := UserClaims{
		Username:  username,
		Role:      role,
		OrgID:     orgID,
		ProjectID: projectID,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   username,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			NotBefore: jwt.NewNumericDate(now.Add(-30 * time.Second)),
		},
	}
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return t.SignedString(secret)
}
