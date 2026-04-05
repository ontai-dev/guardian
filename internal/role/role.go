// Package role defines the Guardian deployment role model.
//
// Guardian is a single binary with two declared deployment roles injected via the
// GUARDIAN_ROLE environment variable. The role is read once at startup before any
// controller or gRPC server initialisation. An absent or invalid role causes an
// immediate structured exit. guardian-schema.md §15.
package role

import (
	"fmt"
	"os"
)

// Role is the Guardian deployment role, injected via GUARDIAN_ROLE at startup.
// guardian-schema.md §15.
type Role string

const (
	// RoleManagement is deployed exclusively on the management cluster by compiler enable.
	// Registers: PolicyReconciler, ProfileReconciler, IdentityProviderReconciler,
	// IdentityBindingReconciler, PermissionSetReconciler, EPGReconciler,
	// BootstrapController, AuditSinkReconciler. guardian-schema.md §15.
	RoleManagement Role = "management"

	// RoleTenant is optionally deployed on tenant clusters via ClusterPack through Wrapper.
	// Registers: PolicyReconciler, ProfileReconciler, IdentityProviderReconciler,
	// IdentityBindingReconciler, BootstrapController, AuditForwarderController.
	// guardian-schema.md §15.
	RoleTenant Role = "tenant"
)

// ExitFn is the function called when GUARDIAN_ROLE validation fails. It defaults to
// os.Exit and can be replaced in tests to capture the exit signal without terminating
// the test process.
var ExitFn = func(code int) { os.Exit(code) }

// ParseRole validates val as a Role and returns it. Returns an error if val is
// empty or not one of the declared values. ParseRole never calls ExitFn — callers
// decide whether a parse failure is fatal.
func ParseRole(val string) (Role, error) {
	switch Role(val) {
	case RoleManagement:
		return RoleManagement, nil
	case RoleTenant:
		return RoleTenant, nil
	default:
		if val == "" {
			return "", fmt.Errorf("GUARDIAN_ROLE environment variable is absent; set it to %q or %q",
				string(RoleManagement), string(RoleTenant))
		}
		return "", fmt.Errorf("GUARDIAN_ROLE=%q is not a valid role; valid values: %q, %q",
			val, string(RoleManagement), string(RoleTenant))
	}
}

// ReadFromEnv reads the GUARDIAN_ROLE environment variable, validates it, and
// returns the Role. If the variable is absent or invalid, it prints a FATAL
// message to stderr and calls ExitFn(1). This function must be called at the
// very start of main, before any controller or gRPC server initialisation.
// guardian-schema.md §15.
func ReadFromEnv() Role {
	val := os.Getenv("GUARDIAN_ROLE")
	r, err := ParseRole(val)
	if err != nil {
		fmt.Fprintf(os.Stderr,
			"FATAL: %s\nGuardian refuses to start without a valid role. See guardian-schema.md §15.\n",
			err)
		ExitFn(1)
		return "" // unreachable; satisfies the compiler after ExitFn
	}
	return r
}
