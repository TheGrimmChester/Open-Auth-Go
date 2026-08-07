# Changelog

## Unreleased

- `EnforceProjectACL`: missing / `all` org resolves from JWT `org_id` or denies —
  never invents `DefaultOrganizationID`.
- Optional `impersonator` claim on user JWTs (`MintUserJWTWithImpersonator`);
  mint/verify round-trip; opaque to middleware (target `account_type` drives tenancy).
- List-only `X-Project-IDs` / `project_ids`: `EnforceProjectACL` checks every id;
  rejects over `MaxProjectIDs` (32) with `ErrTooManyProjectIDs` (HTTP 400 via
  middleware). Single `X-Project-ID` path unchanged.
- Per-user project ACLs: `project_ids` claim, `MintUserJWTWithACL`, `CanAccessProject` / `EnforceProjectACL`, and `LocalIssuer` membership (`RegisterWithMembership`, `SetMembership`). Role `admin` bypasses the allowlist (lab seed admin keeps full org access).
- User JWTs may carry optional `org_id` / `project_id` (`MintUserJWTWithTenant`); middleware enforces header match via `ApplyUserTenantHeaders`.
- Add HTTP middleware (`RequireUser`, `RequireUserOrService`), `Gate` / `Bootstrap`, `LocalAuthHandlers`, `LoadJWTSecret`, `BearerOrCookie`, and `HasPermission`.
- Add `MintUserJWT`, `ResolveMode` / `ModeStandalone` / `ModeCodeployed`, and `LocalIssuer` for per-product standalone auth.
- Implement user JWT validate and service JWT mint/validate (`iss`/`aud`/`scope`).
