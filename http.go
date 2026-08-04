package openauth

import (
	"net/http"
	"strings"
)

// CookieName is the default HttpOnly cookie used by Open-* dashboards for JWTs.
const CookieName = "opa_token"

// BearerOrCookie extracts a JWT from Authorization: Bearer or the named cookie.
// Empty cookieName defaults to CookieName.
func BearerOrCookie(r *http.Request, cookieName string) string {
	if r == nil {
		return ""
	}
	if cookieName == "" {
		cookieName = CookieName
	}
	if authHeader := r.Header.Get("Authorization"); authHeader != "" {
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
			return strings.TrimSpace(parts[1])
		}
		return ""
	}
	if c, err := r.Cookie(cookieName); err == nil {
		return c.Value
	}
	return ""
}
