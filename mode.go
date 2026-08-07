package openauth

import "strings"

// Mode selects how a product issues and validates user JWTs.
type Mode string

const (
	// ModeStandalone: the product issues and validates JWTs with its own JWT_SECRET.
	ModeStandalone Mode = "standalone"
	// ModeCodeployed: OAM (iss=oam-api) issues user JWTs when PEER_OAM_URL is set;
	// products validate with a shared JWT_SECRET. Local /api/auth/login is not the
	// identity home (hub may proxy login to OAM).
	ModeCodeployed Mode = "codeployed"
)

// ResolveMode picks standalone vs co-deployed auth.
//
// Rules (first match wins):
//  1. AUTH_MODE=standalone → standalone
//  2. AUTH_MODE=codeployed (or hub / shared) → codeployed
//  3. Empty AUTH_MODE: standalone when peerHubURL is empty; otherwise codeployed
//
// peerHubURL is typically PEER_OPA_URL (hub base URL). User JWT issuance in
// family stacks belongs to OAM when PEER_OAM_URL is set; the hub validates and
// may proxy login. Pass "" for products that always use explicit AUTH_MODE.
func ResolveMode(authModeEnv, peerHubURL string) Mode {
	switch strings.ToLower(strings.TrimSpace(authModeEnv)) {
	case "standalone", "local", "solo":
		return ModeStandalone
	case "codeployed", "co-deployed", "shared", "hub":
		return ModeCodeployed
	}
	if strings.TrimSpace(peerHubURL) == "" {
		return ModeStandalone
	}
	return ModeCodeployed
}

// IsStandalone reports whether mode is standalone.
func IsStandalone(mode Mode) bool {
	return mode == ModeStandalone
}
