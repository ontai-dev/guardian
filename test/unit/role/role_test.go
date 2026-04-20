// Package role_test covers the GUARDIAN_ROLE startup gate and controller set mapping.
//
// Tests:
//   - ParseRole: absent value returns error.
//   - ParseRole: invalid value returns error.
//   - ParseRole: "management" returns RoleManagement.
//   - ParseRole: "tenant" returns RoleTenant.
//   - ReadFromEnv: absent GUARDIAN_ROLE calls ExitFn(1).
//   - ReadFromEnv: invalid GUARDIAN_ROLE calls ExitFn(1).
//   - ReadFromEnv: valid GUARDIAN_ROLE does not call ExitFn.
//   - ControllerSetForRole: management set contains AuditSinkReconciler, not AuditForwarder.
//   - ControllerSetForRole: tenant set contains AuditForwarder, not AuditSinkReconciler.
//   - ControllerSetForRole: shared controllers present in both sets.
//
// guardian-schema.md §15.
package role_test

import (
	"testing"

	"github.com/ontai-dev/guardian/internal/role"
)

// ── ParseRole ────────────────────────────────────────────────────────────────

func TestParseRole_AbsentReturnsError(t *testing.T) {
	_, err := role.ParseRole("")
	if err == nil {
		t.Fatal("expected error for absent GUARDIAN_ROLE, got nil")
	}
}

func TestParseRole_InvalidReturnsError(t *testing.T) {
	_, err := role.ParseRole("invalid-value")
	if err == nil {
		t.Fatal("expected error for invalid GUARDIAN_ROLE, got nil")
	}
}

func TestParseRole_ManagementValid(t *testing.T) {
	r, err := role.ParseRole("management")
	if err != nil {
		t.Fatalf("unexpected error for valid management role: %v", err)
	}
	if r != role.RoleManagement {
		t.Fatalf("expected RoleManagement, got %q", r)
	}
}

func TestParseRole_TenantValid(t *testing.T) {
	r, err := role.ParseRole("tenant")
	if err != nil {
		t.Fatalf("unexpected error for valid tenant role: %v", err)
	}
	if r != role.RoleTenant {
		t.Fatalf("expected RoleTenant, got %q", r)
	}
}

// ── ReadFromEnv / ExitFn ─────────────────────────────────────────────────────

func TestReadFromEnv_AbsentRoleCallsExit(t *testing.T) {
	t.Setenv("GUARDIAN_ROLE", "")

	var exitCalled bool
	var exitCode int
	orig := role.ExitFn
	role.ExitFn = func(code int) {
		exitCalled = true
		exitCode = code
	}
	defer func() { role.ExitFn = orig }()

	role.ReadFromEnv()

	if !exitCalled {
		t.Fatal("expected ExitFn to be called for absent GUARDIAN_ROLE")
	}
	if exitCode != 1 {
		t.Fatalf("expected exit code 1, got %d", exitCode)
	}
}

func TestReadFromEnv_InvalidRoleCallsExit(t *testing.T) {
	t.Setenv("GUARDIAN_ROLE", "not-a-valid-role")

	var exitCalled bool
	orig := role.ExitFn
	role.ExitFn = func(code int) { exitCalled = true }
	defer func() { role.ExitFn = orig }()

	role.ReadFromEnv()

	if !exitCalled {
		t.Fatal("expected ExitFn to be called for invalid GUARDIAN_ROLE")
	}
}

func TestReadFromEnv_ValidRoleDoesNotCallExit(t *testing.T) {
	t.Setenv("GUARDIAN_ROLE", "management")

	exitCalled := false
	orig := role.ExitFn
	role.ExitFn = func(code int) { exitCalled = true }
	defer func() { role.ExitFn = orig }()

	r := role.ReadFromEnv()

	if exitCalled {
		t.Fatal("ExitFn must not be called for a valid GUARDIAN_ROLE")
	}
	if r != role.RoleManagement {
		t.Fatalf("expected RoleManagement, got %q", r)
	}
}

// ── ControllerSetForRole ─────────────────────────────────────────────────────

func containsController(set []role.ControllerName, name role.ControllerName) bool {
	for _, n := range set {
		if n == name {
			return true
		}
	}
	return false
}

func TestControllerSetForRole_ManagementContainsAuditSink(t *testing.T) {
	set := role.ControllerSetForRole(role.RoleManagement)
	if !containsController(set, role.ControllerAuditSink) {
		t.Fatalf("management role must include %s; got %v", role.ControllerAuditSink, set)
	}
}

func TestControllerSetForRole_ManagementDoesNotContainAuditForwarder(t *testing.T) {
	set := role.ControllerSetForRole(role.RoleManagement)
	if containsController(set, role.ControllerAuditForwarder) {
		t.Fatalf("management role must NOT include %s", role.ControllerAuditForwarder)
	}
}

func TestControllerSetForRole_TenantContainsAuditForwarder(t *testing.T) {
	set := role.ControllerSetForRole(role.RoleTenant)
	if !containsController(set, role.ControllerAuditForwarder) {
		t.Fatalf("tenant role must include %s; got %v", role.ControllerAuditForwarder, set)
	}
}

func TestControllerSetForRole_TenantDoesNotContainAuditSink(t *testing.T) {
	set := role.ControllerSetForRole(role.RoleTenant)
	if containsController(set, role.ControllerAuditSink) {
		t.Fatalf("tenant role must NOT include %s", role.ControllerAuditSink)
	}
}

func TestControllerSetForRole_SharedControllersInBothRoles(t *testing.T) {
	shared := []role.ControllerName{
		role.ControllerRBACPolicy,
		role.ControllerRBACProfile,
		role.ControllerIdentityProvider,
		role.ControllerIdentityBinding,
		role.ControllerBootstrap,
	}

	for _, r := range []role.Role{role.RoleManagement, role.RoleTenant} {
		set := role.ControllerSetForRole(r)
		for _, name := range shared {
			if !containsController(set, name) {
				t.Errorf("role=%s must include shared controller %s", r, name)
			}
		}
	}
}
