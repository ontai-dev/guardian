# Development Standard

> This document defines the development standard for ont-security.
> Every agent reads this before beginning implementation work.

---

## 1. Controller Structure

ont-security has four reconcilers and one admission webhook server.

**RBACPolicyReconciler** — watches RBACPolicy. Validates structure. Updates status.
No Job submission — policy validation is in-process.

**RBACProfileReconciler** — watches RBACProfile. Validates against governing
RBACPolicy. Computes effective permissions for the principal. Sets provisioned=true
on success. Never provisioned=true unless all validation passes. Triggers EPG
recomputation when a profile changes.

**EPGReconciler** — watches for changes across RBACPolicy, RBACProfile,
IdentityBinding, PermissionSet. On any change: recomputes EPG, generates new
PermissionSnapshot, pushes to target cluster agents, records delivery status.

**IdentityBindingReconciler** — watches IdentityBinding. Validates trust method
constraints (token max TTL, mTLS requirement). Triggers EPG recomputation on change.

**Admission Webhook Server** — intercepts Role, ClusterRole, RoleBinding,
ClusterRoleBinding, ServiceAccount creates and updates. Rejects any resource
without ontai.dev/rbac-owner=ont-security annotation. During bootstrap RBAC window
only: allows resources that match the bootstrap RBACPolicy. Window closes on first
successful webhook registration. INV-020.

---

## 2. EPG Computation Model

The EPG is a directed graph. Nodes are principals. Edges are permissions.
Computation inputs: all active RBACProfiles, their governing RBACPolicies, all
IdentityBindings, all PermissionSets.

Computation is fully in-process. No external calls during computation. The result
is a map of principal → cluster → allowed operations. This map is serialized into
a PermissionSnapshot.

Computation is triggered by any input change. It is idempotent. Given the same
inputs, it always produces the same output. Tests must verify this property.

---

## 3. Two-Phase Boot Implementation

The controller startup sequence is explicit and deterministic:

Phase 1 entry: operator starts. Database connection is not attempted. CRD-only
persistence mode is active. The controller processes bootstrap RBACPolicy from
git-applied CR. It provisions CNPG's, cert-manager's, Kueue's, metallb's, and
its own RBACProfiles. All state in CRD status. Admission webhook starts immediately.

Phase 2 trigger: the EPGReconciler watches for CNPG cluster readiness. When CNPG
reaches ready, the controller initiates database migration: transfers current EPG
state and audit log to CNPG, switches persistence mode to database-backed, sets
EnableComplete on the management cluster's RunnerConfig.

Phase 2 is idempotent. If CNPG is already available on startup (management cluster
rebuild scenario), Phase 1 is abbreviated — the controller reads existing state
from CNPG immediately.

---

## 4. Third-Party RBAC Ownership Protocol

When a new third-party component is installed via the enable phase:

1. Runner splits the Helm chart rendered output into RBAC resources and workload
   resources before applying anything.
2. RBAC resources are submitted to ont-security's intake endpoint (a dedicated
   webhook path, not the production admission webhook).
3. ont-security evaluates the RBAC against the governing RBACPolicy for the
   management cluster. If compliant: creates a RBACProfile for the component,
   annotates resources with ontai.dev/rbac-owner=ont-security, applies them.
4. Workload resources are then applied via normal kube goclient.

This sequence is enforced in the runner enable phase — it is not voluntary.

---

## 5. PermissionService gRPC Implementation

The PermissionService server reads exclusively from the current in-memory EPG
(backed by CNPG). It does not query Kubernetes for each request. The EPG is
kept current by the EPGReconciler.

ExplainDecision traces the full computation path: which RBACPolicy → which
RBACProfile → which PermissionSet → final decision. The trace is written to the
CNPG audit log as well as returned in the response.

---

## 6. Testing Standard

Security tests are the highest-scrutiny tests in the platform.

Unit tests: EPG computation correctness, policy validation logic, admission webhook
decision logic. Every edge case in permission inheritance must be covered.

Integration tests: full policy → profile → snapshot → delivery cycle against
envtest. Verify admission webhook blocks correctly. Verify bootstrap window closes.

e2e tests: deploy ont-security on ccs-test. Verify no RBAC resource lands on
the cluster without ownership annotation. Verify DegradedSecurityState triggers
correctly when snapshot delivery fails.

Regression requirement: any EPG computation change must run the full existing
permission test suite before the change is considered safe. No exceptions.

---

*ont-security development standard*
*Amendments appended below with date and rationale.*