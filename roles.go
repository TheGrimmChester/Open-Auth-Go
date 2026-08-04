package openauth

// HasPermission reports whether userRole meets or exceeds requiredRole in the
// standard Open-* hierarchy: viewer < editor < admin.
func HasPermission(userRole, requiredRole string) bool {
	if requiredRole == "" {
		return true
	}
	roleHierarchy := map[string]int{"viewer": 1, "editor": 2, "admin": 3}
	return roleHierarchy[userRole] >= roleHierarchy[requiredRole]
}
