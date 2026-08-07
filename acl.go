package openauth

import (
	"errors"
	"net/http"
	"strings"
)

// Legacy tenant id constants. DefaultOrganizationID may match stored rows when
// that id is explicitly selected; EnforceProjectACL never invents it for a
// missing / "all" org header (use JWT org_id or deny). DefaultProjectID is
// still used when a restricted caller omits the project header and has no
// singular / single-allowlist pin.
const (
	DefaultOrganizationID = "default-org"
	DefaultProjectID      = "default-project"

	// HeaderProjectIDs is the list-only multi-project header (aligned with
	// opentenant.HeaderProjectIDs). Comma-separated; cap MaxProjectIDs.
	HeaderProjectIDs = "X-Project-IDs"

	// MaxProjectIDs caps X-Project-IDs / project_ids (aligned with Open-Tenant-Go).
	MaxProjectIDs = 32
)

// ErrProjectDenied is returned when the caller is not allowed to access the
// requested project within their organization.
var ErrProjectDenied = errors.New("project access denied")

// ErrTooManyProjectIDs is returned when X-Project-IDs / project_ids exceeds MaxProjectIDs.
var ErrTooManyProjectIDs = errors.New("too many project ids")

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

// RequestProjectIDs reads list-only X-Project-IDs, then project_ids query when
// the header is empty. Returns ErrTooManyProjectIDs when the raw non-empty
// token count exceeds MaxProjectIDs (before dedupe).
func RequestProjectIDs(r *http.Request) ([]string, error) {
	if r == nil {
		return nil, nil
	}
	raw := strings.TrimSpace(r.Header.Get(HeaderProjectIDs))
	if raw == "" {
		raw = strings.TrimSpace(r.URL.Query().Get("project_ids"))
	}
	if raw == "" {
		return nil, nil
	}
	parts := strings.Split(raw, ",")
	tokens := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		tokens = append(tokens, p)
	}
	if len(tokens) > MaxProjectIDs {
		return nil, ErrTooManyProjectIDs
	}
	return NormalizeProjectIDs(tokens), nil
}

// EnforceProjectACL checks the request's tenant headers against claims.
// Missing / "all" org headers resolve to the JWT org_id; if that is also empty
// the request is denied (never invent DefaultOrganizationID). Missing / "all"
// project headers collapse to DefaultProjectID when there is no singular bind
// or single-allowlist pin, so restricted callers cannot widen project scope by
// omission. When the allowlist has exactly one project and the project header
// is empty/"all", the header is pinned to that project.
//
// List-only X-Project-IDs: every id is ACL-checked; over MaxProjectIDs is
// rejected for all callers (including admin). When the multi header is set,
// omitted single X-Project-ID is not collapsed to default-project (list scope
// uses the multi set). A concrete single X-Project-ID is still checked when present.
func EnforceProjectACL(r *http.Request, claims *UserClaims) error {
	if r == nil || claims == nil {
		return nil
	}

	multi, err := RequestProjectIDs(r)
	if err != nil {
		return err
	}

	if !HasProjectRestriction(claims) {
		return nil
	}

	org := strings.TrimSpace(r.Header.Get("X-Organization-ID"))
	if org == "" || strings.EqualFold(org, "all") {
		org = strings.TrimSpace(claims.OrgID)
		if org == "" {
			return ErrProjectDenied
		}
	}

	if len(multi) > 0 {
		for _, id := range multi {
			if !CanAccessProject(claims, org, id) {
				return ErrProjectDenied
			}
		}
		proj := strings.TrimSpace(r.Header.Get("X-Project-ID"))
		if proj != "" && !strings.EqualFold(proj, "all") {
			if !CanAccessProject(claims, org, proj) {
				return ErrProjectDenied
			}
		}
		r.Header.Set("X-Organization-ID", org)
		return nil
	}

	proj := strings.TrimSpace(r.Header.Get("X-Project-ID"))
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
