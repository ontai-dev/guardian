package role

// ControllerName is a string identifier for a controller registered in Guardian.
// It is the canonical source of the role-to-controller mapping.
// guardian-schema.md §15.
type ControllerName string

const (
	ControllerRBACPolicy       ControllerName = "RBACPolicyReconciler"
	ControllerRBACProfile      ControllerName = "RBACProfileReconciler"
	ControllerIdentityProvider ControllerName = "IdentityProviderReconciler"
	ControllerIdentityBinding  ControllerName = "IdentityBindingReconciler"
	ControllerBootstrap        ControllerName = "BootstrapController"

	// Management-only controllers.
	ControllerPermissionSet   ControllerName = "PermissionSetReconciler"
	ControllerEPG             ControllerName = "EPGReconciler"
	ControllerAuditSink       ControllerName = "AuditSinkReconciler"
	ControllerAPIGroupSweep   ControllerName = "APIGroupSweepController"

	// Tenant-only controllers.
	ControllerAuditForwarder ControllerName = "AuditForwarderController"
)

// sharedControllers are registered for both roles.
var sharedControllers = []ControllerName{
	ControllerRBACPolicy,
	ControllerRBACProfile,
	ControllerIdentityProvider,
	ControllerIdentityBinding,
	ControllerBootstrap,
}

// ControllerSetForRole returns the ordered list of controller names that Guardian
// registers for the given role. PermissionService gRPC runs in both roles and is
// not listed here — it is started independently of the controller manager.
// guardian-schema.md §15.
func ControllerSetForRole(r Role) []ControllerName {
	set := make([]ControllerName, len(sharedControllers))
	copy(set, sharedControllers)

	switch r {
	case RoleManagement:
		return append(set,
			ControllerPermissionSet,
			ControllerEPG,
			ControllerAuditSink,
			ControllerAPIGroupSweep,
		)
	case RoleTenant:
		return append(set,
			ControllerAuditForwarder,
		)
	default:
		return set
	}
}
