package openauth

import (
	"errors"
	"net/http"
	"strings"
)

// Lab / WriteTenant defaults (aligned with Open-Tenant-Go). Used when a
// restricted caller omits tenant headers so ACL checks match SQL scope.
const (
	DefaultOrganizationID = "default-org"
	DefaultProjectID      = "default-project"
)

// ErrProjectDenied is returned when the caller is not allowed to access the
// requested project within their organization.
var ErrProjectDenied = errors.New("project access denied")

// HasProjectRestriction reports whether claims carry a project allowlist or a
// singular project bind. Admins are never treated as restricted.
func HasProjectRestriction(claims *UserClaims) bool {
	if claims == nil || HasPermission(claims.Role, "admin") {
		return false
	}
	if strings.TrimSpace(claims.ProjectID) != "" {
		return true
	}
	return len(NormalizeProjectIDs(claims.ProjectIDs)) > 0
}

// NormalizeProjectIDs trims, drops empties/duplicates, and preserves order.
func NormalizeProjectIDs(ids []string) []string {
	if len(ids) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(ids))
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" || strings.EqualFold(id, "all") {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// CanAccessProject reports whether claims may read/write the given org/project.
//
// Rules (first match):
//  1. nil claims → deny
//  2. role admin → allow (full org access; lab seed admin stays unlocked)
//  3. OrgID claim set and orgID mismatches → deny
//  4. singular ProjectID claim set → must equal projectID
//  5. ProjectIDs allowlist non-empty → projectID must be a member
//  6. otherwise → allow (legacy unbound token)
func CanAccessProject(claims *UserClaims, orgID, projectID string) bool {
	if claims == nil {
		return false
	}
	orgID = strings.TrimSpace(orgID)
	projectID = strings.TrimSpace(projectID)
	if HasPermission(claims.Role, "admin") {
		return true
	}
	if bound := strings.TrimSpace(claims.OrgID); bound != "" {
		if orgID == "" || orgID != bound {
			return false
		}
	}
	if boundProj := strings.TrimSpace(claims.ProjectID); boundProj != "" {
		return projectID != "" && projectID == boundProj
	}
	allowed := NormalizeProjectIDs(claims.ProjectIDs)
	if len(allowed) == 0 {
		return true
	}
	if projectID == "" {
		return false
	}
	for _, id := range allowed {
		if id == projectID {
			return true
		}
	}
	return false
}

// EnforceProjectACL checks the request's tenant headers against claims.
// Missing / "all" headers collapse to DefaultOrganizationID / DefaultProjectID
// for restricted callers so they cannot widen scope by omission. When the
// allowlist has exactly one project and the project header is empty/"all",
// the header is pinned to that project (same convenience as a singular bind).
func EnforceProjectACL(r *http.Request, claims *UserClaims) error {
	if r == nil || claims == nil {
		return nil
	}
	if !HasProjectRestriction(claims) {
		return nil
	}

	org := strings.TrimSpace(r.Header.Get("X-Organization-ID"))
	proj := strings.TrimSpace(r.Header.Get("X-Project-ID"))
	if org == "" || strings.EqualFold(org, "all") {
		org = DefaultOrganizationID
	}
	if proj == "" || strings.EqualFold(proj, "all") {
		if allowed := NormalizeProjectIDs(claims.ProjectIDs); len(allowed) == 1 && strings.TrimSpace(claims.ProjectID) == "" {
			proj = allowed[0]
		} else if p := strings.TrimSpace(claims.ProjectID); p != "" {
			proj = p
		} else {
			proj = DefaultProjectID
		}
	}

	if !CanAccessProject(claims, org, proj) {
		return ErrProjectDenied
	}
	r.Header.Set("X-Organization-ID", org)
	r.Header.Set("X-Project-ID", proj)
	return nil
}
