package openauth

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ErrInvalidToken is returned when a JWT fails validation.
var ErrInvalidToken = errors.New("invalid token")

// ErrMissingScope is returned when a service JWT lacks a required scope.
var ErrMissingScope = errors.New("missing scope")

// ErrTenantMismatch is returned when request org/project headers conflict with
// JWT-bound tenant claims.
var ErrTenantMismatch = errors.New("tenant mismatch")

const defaultServiceTTL = 5 * time.Minute

// ServiceClaims are peer service-to-service JWT claims.
type ServiceClaims struct {
	Scope  string `json:"scope"`
	OrgID  string `json:"org_id,omitempty"`
	UserID string `json:"user_id,omitempty"`
	jwt.RegisteredClaims
}

// Immutable account types minted by OAM at user creation.
const (
	AccountTypePersonal     = "personal"
	AccountTypeOrganization = "organization"
)

// UserClaims are user-facing JWT claims (validated against JWT_SECRET).
// OrgID / ProjectID optionally bind the token to a tenant; empty means the
// caller may still pass X-Organization-ID / X-Project-ID (lab / unbound admin).
// AccountType is set by OAM ("personal" | "organization") and makes org binding
// explicit rather than inferred from empty org_id alone.
// ProjectIDs is an allowlist of projects within OrgID (or the request org when
// OrgID is empty). Role admin ignores ProjectIDs and may access every project.
// Impersonator is set by OAM when an admin mints a short-lived token as a
// target user; peers treat it as opaque (tenancy follows the target claims).
type UserClaims struct {
	Username     string   `json:"username"`
	Role         string   `json:"role"`
	AccountType  string   `json:"account_type,omitempty"`
	OrgID        string   `json:"org_id,omitempty"`
	ProjectID    string   `json:"project_id,omitempty"`
	ProjectIDs   []string `json:"project_ids,omitempty"`
	Impersonator string   `json:"impersonator,omitempty"`
	jwt.RegisteredClaims
}

// ValidateUserJWT validates a user-facing JWT against JWT_SECRET (HS256).
func ValidateUserJWT(token string, secret []byte) error {
	_, err := ParseUserJWT(token, secret)
	return err
}

// ParseUserJWT parses and validates a user JWT, returning claims.
func ParseUserJWT(token string, secret []byte) (*UserClaims, error) {
	if token == "" || len(secret) == 0 {
		return nil, ErrInvalidToken
	}
	parsed, err := jwt.ParseWithClaims(token, &UserClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("%w: unexpected alg", ErrInvalidToken)
		}
		return secret, nil
	}, jwt.WithValidMethods([]string{"HS256"}))
	if err != nil || !parsed.Valid {
		return nil, ErrInvalidToken
	}
	claims, ok := parsed.Claims.(*UserClaims)
	if !ok {
		return nil, ErrInvalidToken
	}
	return claims, nil
}

// MintServiceJWT mints a short-lived service JWT for peer calls.
// Claims: iss (caller), aud (callee), sub=service, scope, short exp.
func MintServiceJWT(secret []byte, iss, aud, scope string) (string, error) {
	return MintServiceJWTWithTenant(secret, iss, aud, scope, "", "", defaultServiceTTL)
}

// MintServiceJWTWithOrg mints a service JWT with optional org_id and TTL.
func MintServiceJWTWithOrg(secret []byte, iss, aud, scope, orgID string, ttl time.Duration) (string, error) {
	return MintServiceJWTWithTenant(secret, iss, aud, scope, orgID, "", ttl)
}

// MintServiceJWTWithTenant mints a service JWT with optional org_id, user_id, and TTL.
// user_id authorizes personal (empty-org, user-scoped) peer resources without inventing an org.
func MintServiceJWTWithTenant(secret []byte, iss, aud, scope, orgID, userID string, ttl time.Duration) (string, error) {
	if len(secret) == 0 || iss == "" || aud == "" {
		return "", ErrInvalidToken
	}
	if ttl <= 0 {
		ttl = defaultServiceTTL
	}
	now := time.Now().UTC()
	claims := ServiceClaims{
		Scope:  strings.TrimSpace(scope),
		OrgID:  strings.TrimSpace(orgID),
		UserID: strings.TrimSpace(userID),
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    iss,
			Audience:  jwt.ClaimStrings{aud},
			Subject:   "service",
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			NotBefore: jwt.NewNumericDate(now.Add(-30 * time.Second)),
		},
	}
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return t.SignedString(secret)
}

// ValidateServiceJWT validates iss/aud/sub and returns claims.
// expectedAud must match the callee product id (e.g. "osa-api").
func ValidateServiceJWT(token string, secret []byte, expectedAud string) (*ServiceClaims, error) {
	if token == "" || len(secret) == 0 || expectedAud == "" {
		return nil, ErrInvalidToken
	}
	parsed, err := jwt.ParseWithClaims(token, &ServiceClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("%w: unexpected alg", ErrInvalidToken)
		}
		return secret, nil
	}, jwt.WithValidMethods([]string{"HS256"}), jwt.WithAudience(expectedAud))
	if err != nil || !parsed.Valid {
		return nil, ErrInvalidToken
	}
	claims, ok := parsed.Claims.(*ServiceClaims)
	if !ok || claims.Issuer == "" {
		return nil, ErrInvalidToken
	}
	// "service" = long-lived peer identity; "job" = short-lived job token (revocable via jti allowlist).
	switch claims.Subject {
	case "service", "job":
	default:
		return nil, ErrInvalidToken
	}
	return claims, nil
}

// RequireScope returns ErrMissingScope when claims do not include required.
// Scope is a space-separated list (OAuth-style).
func RequireScope(claims *ServiceClaims, required string) error {
	if claims == nil || required == "" {
		return ErrMissingScope
	}
	for _, s := range strings.Fields(claims.Scope) {
		if s == required {
			return nil
		}
	}
	return ErrMissingScope
}
