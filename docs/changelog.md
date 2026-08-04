# Changelog

## Unreleased

- Per-user project ACLs: `project_ids` claim, `MintUserJWTWithACL`, `CanAccessProject` / `EnforceProjectACL`, and `LocalIssuer` membership (`RegisterWithMembership`, `SetMembership`). Role `admin` bypasses the allowlist (lab seed admin keeps full org access).
- User JWTs may carry optional `org_id` / `project_id` (`MintUserJWTWithTenant`); middleware enforces header match via `ApplyUserTenantHeaders`.
- Add HTTP middleware (`RequireUser`, `RequireUserOrService`), `Gate` / `Bootstrap`, `LocalAuthHandlers`, `LoadJWTSecret`, `BearerOrCookie`, and `HasPermission`.
- Add `MintUserJWT`, `ResolveMode` / `ModeStandalone` / `ModeCodeployed`, and `LocalIssuer` for per-product standalone auth.
- Implement user JWT validate and service JWT mint/validate (`iss`/`aud`/`scope`).
