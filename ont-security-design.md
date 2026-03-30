# Development Standard

> This document defines the development standard for ont-security.
> Every agent reads this before beginning implementation work.

---

## 1. Controller Structure

ont-security runs exclusively on the management cluster. It has four reconcilers
and one admission webhook server. There is no ont-security controller Deployment
on target clusters.

Target cluster security plane responsibilities — admission webhook, PermissionSnapshot
receipt, local PermissionService, RBAC drift detection — are hosted by the ont-agent
Deployment in ont-system on each target cluster. See ont-runner-design.md Section 2.10
for the ont-agent security subcomponents. The implementation of those subcomponents
shares the webhook logic and snapshot evaluation packages from the ont-runner shared
library.

**RBACPolicyReconciler** — watches RBACPolicy. Validates structure. Updates status.
No Job submission — policy validation is in-process.

**RBACProfileReconciler** — watches RBACProfile. Validates against governing
RBACPolicy. Computes effective permissions for the principal. Sets provisioned=true
on success. Never provisioned=true unless all validation passes. Triggers EPG
recomputation when a profile changes.

**EPGReconciler** — watches for changes across RBACPolicy, RBACProfile,
IdentityBinding, PermissionSet. On any change: recomputes EPG, generates new
PermissionSnapshot, writes it to security-system. The management cluster ont-agent
signing loop then picks it up and signs it before delivery to target cluster agents.

**IdentityBindingReconciler** — watches IdentityBinding. Validates trust method
constraints (token max TTL, mTLS requirement). Triggers EPG recomputation on change.

**Admission Webhook Server (management cluster)** — intercepts Role, ClusterRole,
RoleBinding, ClusterRoleBinding, ServiceAccount creates and updates on the management
cluster. Rejects any resource without ontai.dev/rbac-owner=ont-security annotation.
During bootstrap RBAC window only: allows resources that match the bootstrap RBACPolicy.
Window closes on first successful webhook registration. INV-020.

The admission webhook on target clusters is hosted by ont-agent, not by this
controller. The webhook logic is shared via the ont-runner shared library package
to ensure identical enforcement behavior.

---

## 2. EPG Computation Model

The EPG is a directed graph. Nodes are principals. Edges are permissions.
Computation inputs: all active RBACProfiles (provisioned=true only), their governing
RBACPolicies, all IdentityBindings (valid only), all PermissionSets.

Computation is fully in-process in the EPGReconciler. No external calls during
computation. The result is a map of principal → cluster → allowed operations. This
map is serialized into a PermissionSnapshot.

The effective permission for a principal on a cluster is the intersection of:
- The permissions declared in the principal's RBACProfile declarations, and
- The ceiling defined by the governing RBACPolicy's MaximumPermissionSetRef.

A principal cannot exercise permissions not covered by the policy ceiling regardless
of what is declared in their profile. The EPG computation enforces this ceiling at
compute time.

Computation is triggered by any input change via the ontai.dev/epg-recompute-requested
annotation signal. It is idempotent. Given the same inputs, it always produces the
same output. Tests must verify this property.

---

## 3. Two-Phase Boot Implementation

The controller startup sequence is explicit and deterministic. Applies to the
management cluster only.

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

1. ont-runner (compile mode) splits the Helm chart rendered output into RBAC
   resources and workload resources before applying anything.
2. RBAC resources are submitted to ont-security's intake endpoint (a dedicated
   webhook path, not the production admission webhook).
3. ont-security evaluates the RBAC against the governing RBACPolicy for the
   management cluster. If compliant: creates a RBACProfile for the component,
   annotates resources with ontai.dev/rbac-owner=ont-security, applies them.
4. Workload resources are then applied via normal kube goclient.

This sequence is enforced in the ont-runner enable phase — it is not voluntary.

Any new ONT operator joining the stack must request RBAC from ont-security before
its controller starts. This is not optional. The RBACProfile provisioned=true gate
blocks the controller. The operator's RBACProfile must be submitted via the intake
protocol and reach provisioned=true before the operator's controller is considered
enabled. INV-003.

---

## 5. PermissionService gRPC Implementation (Management Cluster)

The management cluster PermissionService server reads exclusively from the current
in-memory EPG (backed by CNPG). It does not query Kubernetes for each request. The
EPG is kept current by the EPGReconciler.

ExplainDecision traces the full computation path: which RBACPolicy → which
RBACProfile → which PermissionSet → final decision. The trace is written to the
CNPG audit log as well as returned in the response.

The target cluster PermissionService is hosted by ont-agent and is a read-only
projection from the acknowledged PermissionSnapshotReceipt. It does not connect
to CNPG. Implementation is in the ont-runner shared library, consumed by both
ont-security (management cluster) and ont-agent (target clusters).

---

## 6. PermissionSnapshot Lifecycle

The EPGReconciler generates PermissionSnapshot CRs in security-system. After
generation, the ont-security controller does not sign them. Signing is the
responsibility of the management cluster ont-agent signing loop.

The lifecycle is:
1. EPGReconciler computes EPG, writes PermissionSnapshot (Status.Drift=true,
   signature annotation absent).
2. Management cluster ont-agent signing loop detects unsigned PermissionSnapshot,
   signs it with the platform key, writes signature annotation.
3. Target cluster ont-agent pull loop detects new version, pulls snapshot, verifies
   signature against embedded platform public key.
4. On successful verification: ont-agent writes PermissionSnapshotReceipt with
   acknowledgement, updates local RBAC artifacts.
5. Management cluster ont-agent receipt observation loop detects acknowledgement,
   updates PermissionSnapshot Status.LastAckedVersion, sets Status.Drift=false.

The ont-security controller is responsible for steps 1 and 5 (partial). It is not
responsible for steps 2, 3, or 4. Those belong to ont-agent.

---

## 7. Testing Standard

Security tests are the highest-scrutiny tests in the platform.

Unit tests: EPG computation correctness (including ceiling intersection),
policy validation logic, admission webhook decision logic. Every edge case in
permission inheritance must be covered.

Integration tests: full policy → profile → snapshot → delivery cycle against
envtest. Verify admission webhook blocks correctly. Verify bootstrap window closes.

e2e tests: deploy ont-security on ccs-test. Verify no RBAC resource lands on
the cluster without ownership annotation. Verify DegradedSecurityState triggers
correctly when snapshot delivery fails.

Regression requirement: any EPG computation change must run the full existing
permission test suite before the change is considered safe. No exceptions.

Target cluster webhook behavior is tested via ont-agent tests in the ont-runner
repository, not here. The shared webhook logic package has its own unit test suite.

---

*ont-security development standard*
*Amendments appended below with date and rationale.*

2026-03-30 — Scope of ont-security controller clarified as management cluster only.
  Target cluster security plane (admission webhook, receipt management, local
  PermissionService, drift detection) transferred to ont-agent. Section 1 controller
  structure updated. Section 5 PermissionService split into management and target
  contexts. Section 6 PermissionSnapshot lifecycle added to clarify signing
  responsibility boundary between EPGReconciler (generates) and ont-agent (signs,
  delivers, verifies, acknowledges). Testing standard updated: target cluster webhook
  tests belong in ont-runner repository.