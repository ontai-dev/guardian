## guardian: Operational Constraints
> Read ~/ontai/CLAUDE.md first. The constraints below extend the root constitutional document.

### Schema authority
Primary: docs/guardian-schema.md
Supporting: ~/ontai/conductor/docs/conductor-schema.md (RunnerConfig contract)

### Invariants
CS-INV-001 -- The admission webhook is the enforcement mechanism. Policy without enforcement is decoration. The webhook must be operational before any other operator is considered enabled. (root INV-003)
CS-INV-002 -- CNPG is a guardian dependency only. No other component references or accesses the CNPG cluster in security-system. (root INV-016)
CS-INV-003 -- The two-phase boot (CRD-only to database-backed) is a named, explicit transition. It is never a silent fallback.
CS-INV-004 -- The bootstrap RBAC window has a definite close: when the admission webhook becomes operational. The window is documented, bounded, and reconciled on startup. (root INV-020)
CS-INV-005 -- provisioned=true on RBACProfile is set exclusively by this operator. No other controller writes to RBACProfile status.
CS-INV-006 -- Leader election required. Admission webhook requires a stable leader.
CS-INV-007 -- Third-party RBAC ownership is wrapping, not replacement. Helm upgrades must remain safe. Drift is surfaced, not silently overwritten.
INV-005 -- ClusterAssignment references, never owns, cluster/pack/security resources.
INV-015 -- Deletion of TalosCluster never triggers physical cluster destruction. ClusterReset is the only path to cluster destruction.

### Session protocol additions
Step 4a -- Read guardian-design.md in this repository.
Step 4b -- Before implementing any EPG computation change, trace its impact on PermissionSnapshot generation and target cluster delivery. Document the impact in PROGRESS.md before proceeding.
