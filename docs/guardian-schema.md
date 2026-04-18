# guardian-schema
> API Group: security.ontai.dev
> Operator: guardian
> All agents absorb this document. Security is platform-wide.

---

## 1. Domain Boundary

guardian owns all RBAC across the entire platform — management cluster and
every target cluster. It is the only operator with cross-cutting authority. It
is the only operator with genuine in-process intelligence (EPG computation, policy
validation, admission webhook). It is the only operator with a CNPG dependency.

**Absolute rules with no exceptions:**
- No ONT operator or application implements its own authorization logic.
- No component provisions its own Kubernetes RBAC artifacts.
- All authorization flows through guardian's PermissionService.
- guardian's admission webhook gates every RBAC resource on every cluster.
- guardian deploys first. All other operators wait for RBACProfile provisioned=true
  before being considered enabled. INV-003.

**Deployment boundary:**
Guardian is a single binary with two declared deployment roles — see §15 Guardian Role
Model for the complete contract. Role=management is deployed on the management cluster
by compiler enable. Role=tenant is optionally deployed on tenant clusters exclusively
via ClusterPack through Wrapper. Platform never deploys Guardian and never assumes
Guardian is present on any target cluster.

On target clusters without a Guardian ClusterPack: the security plane responsibilities
— admission webhook, PermissionSnapshot receipt, local PermissionService, RBAC
enforcement — are hosted exclusively by the conductor Deployment in ont-system. This
is the default model for all target clusters.

On target clusters running a Guardian ClusterPack (role=tenant or role=management):
Guardian runs alongside Conductor. The role determines which controller sets register
and whether the tenant's security plane is federated with or sovereign from the
management Guardian. Conductor continues to own the admission webhook and
PermissionSnapshotReceipt on all target clusters regardless of Guardian presence.

---

## 2. Namespace Placement

| Resource                   | Namespace                              |
|----------------------------|----------------------------------------|
| RBACPolicy                 | security-system (platform-admin only)  |
| RBACProfile                | tenant-{cluster-name}                  |
| IdentityBinding            | tenant namespace                       |
| PermissionSet              | security-system                        |
| PermissionSnapshot         | security-system (internal)             |
| CNPG cluster               | security-system                        |
| PermissionSnapshotReceipt  | ont-system on target cluster           |

---

## 3. Management Cluster Boot Sequence

**This section supersedes the former Two-Phase Boot model as of 2026-04-05.**

Guardian on the management cluster starts after CNPG is already operational.
Compiler enable phase 0 (00-infrastructure-dependencies) provisions the CNPG operator
and CNPG Cluster CR before Guardian is deployed — see §16 CNPG Deployment Contract and
conductor-schema.md §9 for the six-phase enable bundle structure.

**Guardian startup sequence (management cluster, role=management):**

**Step 1 — Migration runner:**
Before registering any controller, Guardian's startup migration runner connects to the
CNPG instance and applies all pending schema migrations in order. If CNPG is unreachable
at startup, Guardian emits a `CNPGUnreachable` condition on its singleton status CR and
holds in degraded state — all controller reconciliation is suspended, no crash occurs.
Guardian recovers automatically when CNPG becomes reachable and the migration runner
completes successfully. This is the only blocking gate before controller registration.

**Step 2 — Bootstrap RBAC provisioning:**
After the migration runner completes, Guardian provisions its own RBACProfile from the
bootstrap RBACPolicy (compiled into git at compile time), CNPG's RBAC, cert-manager's
RBAC, Kueue's RBAC, metallb's RBAC. All state written to CRD status and CNPG. The
conductor enable phase installs these components in this window with their RBAC already
provisioned by guardian before installation begins.

**Step 3 — Controller registration:**
All role-gated controllers register (see §15 for the role=management controller set).
The admission webhook becomes operational. The bootstrap RBAC window closes.

If the management cluster is rebuilt, all three steps re-execute in order. The migration
runner is idempotent — it applies only unapplied migrations and is safe to re-run.

---

## 4. Bootstrap RBAC Window

Before guardian's admission webhook is operational on the management cluster,
the conductor enable phase must apply RBAC to install guardian itself. This
window is explicitly declared in the enable phase protocol. The bootstrap RBACPolicy
in git defines exactly what is permitted in this window. As soon as guardian's
webhook becomes operational, the window closes permanently. RBAC applied in this
window is immediately reconciled by guardian on startup — validated and
ownership-annotated if compliant, flagged for remediation if not. INV-020.

On target clusters, the bootstrap RBAC window is handled differently: the conductor
Deployment arrives via the agent ClusterPack deployment. Once the conductor starts
on a target cluster, its admission webhook is immediately operational. There is no
bootstrap RBAC window on target clusters — the agent pack is applied via the
agent bootstrap exception (wrapper-schema.md Section 6) before any webhook exists,
and from that point forward the webhook runs continuously.

---

## 5. Admission Webhook

guardian runs an admission webhook on the management cluster. The webhook
intercepts all creates and updates to: Role, ClusterRole, RoleBinding,
ClusterRoleBinding, ServiceAccount.

Any RBAC resource arriving without annotation ontai.dev/rbac-owner=guardian
is rejected at admission with a structured error. The only path for RBAC resources
to land on the management cluster is through guardian taking ownership first.

**On target clusters:** The admission webhook is hosted by the conductor Deployment
in ont-system, not by a separate guardian controller. The conductor webhook
uses the current PermissionSnapshotReceipt as its authority for admission decisions.
This means target cluster RBAC enforcement is fully operational even when the
management cluster is temporarily unreachable — the conductor serves decisions
from its local acknowledged snapshot state.

The webhook behavior is identical on management and target clusters: any RBAC
resource lacking the ontai.dev/rbac-owner=guardian annotation is rejected.
The implementation in conductor shares the webhook logic package from the shared
library.

---

## 6. Third-Party RBAC Ownership

**LOCKED INVARIANT (partial) — Platform Governor directive 2026-04-05: RBACProfile authorship.**

guardian wraps third-party component RBAC — CNPG, cert-manager, Kueue, metallb,
and future components — into RBACProfiles with ownership annotations.

The model is wrapping, not replacement:
- guardian creates a RBACProfile declaring policy compliance for the component.
- Existing RBAC resources are annotated: ontai.dev/rbac-owner=guardian.
- guardian watches those resources. Drift from the declared RBACProfile raises
  a policy violation. It never silently overwrites.
- The conductor enable phase splits compiled chart output into RBAC resources and
  workload resources. RBAC goes through guardian intake. Workload applies directly.

Any ONT operator joining the stack on the management cluster must, by default, request
RBAC from guardian before its controller starts. The RBACProfile gate (provisioned=true)
blocks all operator controllers until guardian has validated and provisioned their
permission declarations. INV-003.

**RBACProfile authorship — `compiler component`:**
Guardian's admission webhook enforces what RBACProfiles declare. It never generates
RBACProfiles and never guesses what a third-party component needs. The authorship
path for all third-party component RBACProfiles is exclusively `compiler component`:
the Compiler subcommand that emits RBACProfile CRs from an embedded versioned catalog
(Cilium, CNPG, Kueue, cert-manager, local-path-provisioner) or from a human-provided
descriptor for unlisted components. `compiler component` is a prerequisite for any
third-party component operating in a Guardian-governed cluster. No third-party component
may operate without a Guardian-provisioned RBACProfile, and no RBACProfile is authored
at runtime — only at compile time. See conductor-schema.md §16.

**Seam operator RBACProfiles:**
The first-class platform-owned RBACProfiles for Seam operator service accounts
(Guardian, Platform, Wrapper, Conductor, seam-core) are produced by `compiler enable`
as part of the management cluster bootstrap bundle and never modified at runtime.

---

## 7. CRDs — Management Cluster

### RBACPolicy

Scope: Namespaced — security-system. Platform-admin visibility only.
Short name: rp

Governing policy that constrains what RBACProfiles within its scope may declare.
Profiles that exceed their governing policy are rejected at admission.

The bootstrap RBACPolicy for the management cluster is generated by conductor
compile mode and committed to git alongside TalosCluster. It exists on the
management cluster before guardian is installed.

Key spec fields: subjectScope, allowedClusters, maximumPermissionSetRef,
enforcementMode (strict or audit).

---

### RBACProfile

Scope: Namespaced — tenant-{cluster-name}
Short name: rbp

Per-component per-tenant permission declaration. Validated against governing
RBACPolicy before provisioned=true is set. No operator is enabled until its
RBACProfile reaches provisioned=true. INV-003.

Key spec fields: principalRef, targetClusters, permissionDeclarations,
rbacPolicyRef.

Status conditions: Provisioned, ValidationFailed, Pending.

Invariant: provisioned=true is set exclusively by guardian. No other controller
writes to RBACProfile status. CS-INV-005.

---

### IdentityBinding

Scope: Namespaced.
Short name: ib

Maps external identity to ONT permission principal.
Key spec fields: identityType (oidc, serviceAccount, certificate), identity-specific
fields, principalName, trustMethod (mtls default, token requires justification and
max 15-minute TTL).

---

### IdentityProvider

Scope: Namespaced — security-system.
Short name: idp

Declares an external identity source whose assertions Guardian will recognize and
validate. This is distinct from IdentityBinding: IdentityProvider configures the
upstream source — SSO provider, PKI certificate authority, token issuer, OIDC
endpoint — while IdentityBinding maps a specific identity from that source to a
platform permission principal. One IdentityProvider per external identity source.
Multiple IdentityBindings may reference the same IdentityProvider.

Key spec fields: type (oidc, pki, token), issuerURL (for OIDC providers), caBundle
(for PKI providers), tokenSigningKey (for token issuers), allowedAudiences,
validationRules.

Status conditions: Reachable, ValidationFailed, Pending.

**Relationship to IdentityBinding:** Guardian validates IdentityBinding trust
assertions against the IdentityProvider declared for that identity type. An
IdentityBinding without a matching IdentityProvider for its identityType is
rejected at admission. The IdentityProvider is the upstream trust anchor. The
IdentityBinding is the principal assignment.

---

### PermissionSet

Scope: Namespaced — security-system.
Short name: ps

Named reusable permission collection. Platform archetypes created at initialization:
cluster-admin, tenant-admin, pack-executor, viewer.
Key spec fields: permissions (API group, resource, verbs), description.

---

### PermissionSnapshot

Scope: Namespaced — security-system. Internal to guardian.
Short name: psn

Computed, versioned, signed EPG for a specific target cluster. Generated on any
input change by the EPGReconciler. Signed by the management cluster conductor
after generation. Never manually authored. One per target cluster, replaced
in-place on recomputation. Version field provides monotonic ordering.

Delivery tracking fields: expectedVersion, lastAckedVersion, drift, lastSeen.

The signature annotation (ontai.dev/snapshot-signature) is written by the management
cluster conductor signing loop, not by the EPGReconciler. Operators and reconcilers
must not write this annotation. It is validated by target cluster conductor before
receipt acknowledgement.

---

## 8. CRDs — Target Cluster (conductor Managed)

All CRDs in this section are created and maintained exclusively by the conductor
Deployment in ont-system on the target cluster. No separate guardian agent
exists on target clusters. conductor incorporates all target cluster security plane
responsibilities.

### PermissionSnapshotReceipt

Scope: Namespaced — ont-system on target cluster.
Short name: psr

Local record of current acknowledged PermissionSnapshot and provisioned RBAC
artifact status. Created and maintained exclusively by conductor in agent mode.
Never authored manually.

Before writing a receipt acknowledgement, conductor verifies the cryptographic
signature on the PermissionSnapshot against the platform public key embedded in
the conductor binary. Verification failure results in SyncStatus=DegradedSecurityState
and does not advance lastAckedVersion. This prevents a compromised management cluster
from pushing malicious permission snapshots to target clusters.

One PermissionSnapshotReceipt per target cluster. If the management cluster is
rebuilt, it reconstructs delivery status by reading this CR on each cluster.

Key fields (agent-managed): snapshotVersion, acknowledgedAt, localProvisioningStatus,
localArtifacts, syncStatus (InSync, OutOfSync, DegradedSecurityState).

---

## 9. Permission Propagation

Push is optimization. Pull is correctness. Acknowledgement is truth.
Verification is trust.

**Delivery contract:** sign snapshot → push snapshot → agent verifies signature →
agent acknowledges → guardian records.

**SnapshotOutOfSync:** acknowledgement not received within 2× TTL (default 10 min).
Consequence: new PackExecution blocked on affected cluster.

**DegradedSecurityState:** persistent failure beyond extended threshold, or signature
verification failure.
Consequence: no new authorization decisions permitted. Human intervention required.

**Pull loop:** conductor periodically compares local version against management cluster
expected version. Self-heals by pulling and re-verifying. Pull is the correctness
guarantee. Push is the performance optimization.

---

## 10. PermissionService gRPC API

Single runtime authorization decision point. All ONT operators and applications
call this service. No operator queries Kubernetes RBAC API directly.

Operations: CheckPermission, ListPermissions, WhoCanDo, ExplainDecision.

**On management cluster:** the guardian controller exposes the PermissionService
gRPC endpoint backed by the current in-memory EPG (backed by CNPG).

**On target clusters:** conductor in agent mode exposes a local PermissionService
gRPC endpoint in ont-system. Application operators and controllers on the target
cluster call the local agent endpoint. The agent serves decisions from its current
acknowledged PermissionSnapshotReceipt without requiring management cluster
connectivity. This is how future Screen and application operators achieve runtime
authorization without management cluster network dependency.

The local PermissionService implementation in conductor is a read-only projection
of the acknowledged snapshot — it does not compute the EPG. EPG computation is
exclusively a management cluster function in the guardian controller.

PermissionService is the planned QuantAI integration point for AI-proposed
infrastructure operations requiring human gate review.

---

## 11. Execution Gatekeeper

All four conditions must pass before PackExecution is admitted to Kueue. Enforced
by guardian's admission webhook on the management cluster — a hard block, not
a soft check:

1. Target cluster has current, acknowledged, verified PermissionSnapshot.
2. Requesting principal has validated, provisioned RBACProfile.
3. Target cluster is in principal's RBACProfile.targetClusters.
4. Requested operation is within principal's effective permission set.

---

## 12. Tenant Isolation

Three-layer isolation, each independent of the others:
1. Namespace isolation: tenant-{cluster-name} namespace boundary.
2. RBAC enforcement: tenants cannot list cluster-scoped resources globally.
3. Policy-level: guardian validates targetCluster against allowedClusters at
   admission. Bypass via RBAC misconfiguration in layers 1 or 2 is impossible.

---

## 13. CNPG Security Warehouse Access Controls

NetworkPolicy restricts ingress to security-system to guardian pods only.
CNPG credentials are Secrets in security-system with no RBAC bindings for human
users — not even cluster-admin can read them through normal paths.
Audit access for the security team is granted through a designated read-only view
exposed by guardian's PermissionService — never through direct database access.

---

## 14. Cross-Domain Rules

Reads: platform.ontai.dev/QueueProfile to provision Kueue ClusterQueue resources.
Reads: platform.ontai.dev/TalosCluster to detect new cluster registrations and
  create initial RBACProfiles.
Reads: runner.ontai.dev/RunnerConfig status (capability confirmation).
Intercepts: infra.ontai.dev/PackExecution at admission (execution gatekeeper).
Writes: security.ontai.dev resources on management cluster.
Writes: PermissionSnapshotReceipt on target clusters via conductor.
Writes: Kueue ClusterQueue and ResourceFlavor resources (derived from QueueProfile).
Never writes to platform.ontai.dev or infra.ontai.dev CRDs.

The signing annotation (ontai.dev/snapshot-signature) on PermissionSnapshot is
written by the management cluster conductor, not by the guardian controller.
The controller generates the snapshot. The agent signs it. These are sequential,
not concurrent writes.

---

## 15. Guardian Role Model

**LOCKED INVARIANT — Platform Governor directive 2026-04-05.**

Guardian is a single binary with two declared deployment roles. The role is injected as
the startup environment variable `GUARDIAN_ROLE`. Guardian refuses to start if
`GUARDIAN_ROLE` is absent or set to any value other than `management` or `tenant`.
An absent or invalid `GUARDIAN_ROLE` causes an immediate structured exit before any
controller or gRPC server initialisation.

**Role=management:**
Deployed on the management cluster exclusively. Provisioned by compiler enable. The
management cluster Guardian runs with full controller authority: EPG computation,
PermissionSnapshot generation, policy validation, cross-cluster AuditSink, and
PermissionService gRPC. It connects to a management-cluster-local CNPG instance
(provisioned by compiler enable phase 0) for all persistent EPG and audit state.
No human, operator, or pipeline other than compiler enable may stamp role=management
on a Guardian Deployment.

**Role=tenant:**
Deployed on tenant clusters exclusively via ClusterPack through Wrapper. Optional per
tenant choice. Platform never knows whether a tenant has deployed Guardian, and never
depends on its presence. The tenant Guardian always connects to a tenant-local CNPG
instance (provisioned as part of the same ClusterPack). There is no CRD-only mode for
role=tenant — full persistence parity with role=management is the only supported
configuration. The tenant Guardian registers a reduced controller set. Audit forwarding
to the management Guardian is opt-in, controlled exclusively by the
`GUARDIAN_AUDIT_FORWARD` environment variable (default: `false`). Tenant Guardian is
sovereign by default.

**GUARDIAN_AUDIT_FORWARD env var:**
Controls whether the tenant Guardian forwards audit events to the management Guardian.
Injected alongside `GUARDIAN_ROLE` in the Guardian Deployment spec. Only valid for
role=tenant; absent for role=management. Any value other than `true` or `false` causes
an immediate structured exit before controller initialisation. Valid values:

- `false` (default) — **Sovereign mode.** The tenant Guardian is fully sovereign:
  independent CNPG instance, independent identity plane, no audit forwarding to the
  management Guardian, no participation in the cross-cluster audit chain. The management
  Guardian has no knowledge of and no dependency on any tenant Guardian in this mode.
- `true` — **Federated mode.** The tenant Guardian forwards audit events to the
  management Guardian via the Conductor federation channel. Conductor is the transport:
  the tenant Guardian is the audit producer, the management Guardian is the audit
  consumer. The management Guardian processes forwarded events through its AuditSink
  pipeline. The tenant Guardian's AuditForwarderController activates in this mode only.

`GUARDIAN_AUDIT_FORWARD` is a Guardian concern only and has no effect on the Conductor
federation channel. The tenant Conductor connects to the management Conductor for
RunnerConfig validation regardless of Guardian topology. A cross-cluster identity trust
relationship between a tenant Guardian and the management Guardian is established only by
an explicit `federated-downstream` IdentityProvider CR authored by a human — never by
Guardian inference.

**Controller sets registered at startup, gated by role:**

| Controller                  | role=management | role=tenant (GUARDIAN_AUDIT_FORWARD=false) | role=tenant (GUARDIAN_AUDIT_FORWARD=true) |
|-----------------------------|-----------------|-------------------------------------------|------------------------------------------|
| PolicyReconciler            | ✓               | ✓                                         | ✓                                        |
| ProfileReconciler           | ✓               | ✓                                         | ✓                                        |
| IdentityProviderReconciler  | ✓               | ✓                                         | ✓                                        |
| IdentityBindingReconciler   | ✓               | ✓                                         | ✓                                        |
| AuditSinkReconciler         | ✓               | —                                         | —                                        |
| AuditForwarderController    | —               | —                                         | ✓                                        |

PermissionService gRPC runs in both roles. The management Guardian serves authorization
decisions for the management cluster and all tenant Guardians operating in federated mode
(GUARDIAN_AUDIT_FORWARD=true) that forward audit events to it. The tenant Guardian
(role=tenant) serves decisions for its own cluster locally — this supplements, but does
not replace, the Conductor local PermissionService.

This is a locked invariant. The role gating on controller registration is permanent.
Adding a controller to a role that does not include it requires a Platform Governor
constitutional amendment.

---

## 16. CNPG Deployment Contract

**LOCKED INVARIANT — Platform Governor directive 2026-04-05.**

**Management cluster:**
The CNPG operator and CNPG Cluster CR are provisioned by compiler enable as a dedicated
phase 0 of the enable bundle (`00-infrastructure-dependencies`) — before Guardian is
deployed. See conductor-schema.md §9 for the six-phase enable bundle structure. Guardian's
startup migration runner (§3 Step 1) connects to CNPG and applies pending schema
migrations before registering any controller. If CNPG is unreachable at Guardian startup,
Guardian emits a `CNPGUnreachable` condition on its singleton status CR and holds in
degraded state — controller reconciliation is suspended, no crash occurs. Guardian
recovers automatically when CNPG becomes reachable and the migration runner completes.

The CNPG deployment on the management cluster is owned exclusively by compiler enable.
No operator writes CNPG resources on the management cluster. Human review of the enable
bundle must verify phase 0 contents before GitOps application.

**Tenant clusters:**
CNPG on a tenant cluster is provisioned via ClusterPack through Wrapper. It is part of
the Guardian tenant deployment pack — a pack the tenant opts into by creating the
appropriate PackExecution. Platform has no knowledge of or dependency on CNPG on any
tenant cluster. CNPG is invisible to Platform. CNPG is invisible to Conductor unless the
tenant's Guardian pack explicitly wires CNPG connectivity. Wrapper delivers the pack
contents; it does not understand or interpret what those contents include.

**Authority boundary:**
- Management cluster CNPG: owned by compiler enable (phase 0), consumed by Guardian (role=management).
- Tenant cluster CNPG: owned by the tenant's ClusterPack, consumed by tenant Guardian.
- No operator other than Guardian has a CNPG dependency. INV-016.
- Platform never provisions CNPG on any cluster under any circumstance.
- Conductor never provisions CNPG on any cluster under any circumstance.

**F-P8:** compiler enable phase 0 implementation (adding CNPG operator manifests and CNPG
Cluster CR to the enable bundle as 00-infrastructure-dependencies output) requires a
Conductor Engineer session. This is tracked in CONTEXT.md.

---

*security.ontai.dev schema — guardian*
*Amendments appended below with date and rationale.*

2026-03-30 — Target cluster security plane responsibilities transferred to conductor.
  No separate guardian Deployment on target clusters. conductor hosts admission
  webhook, PermissionSnapshotReceipt management, local PermissionService, and drift
  detection on target clusters. Cryptographic signing model added: management cluster
  conductor signs PermissionSnapshot; target cluster conductor verifies before
  acknowledgement. Section 1 domain boundary clarified. Section 5 admission webhook
  updated for two-context model. Section 8 receipt management updated to name conductor
  explicitly. Section 10 PermissionService split into management and target context.
  INV-026 referenced.

2026-04-03 — IdentityProvider CRD added to Section 7. Relationship to IdentityBinding
  formally specified. IdentityProvider is the upstream trust anchor. IdentityBinding is
  the principal assignment. An IdentityBinding without a matching IdentityProvider for
  its identityType is rejected at admission. IdentityProvider is a prerequisite before
  any Controller Engineer session implementing identity trust methods in IdentityBinding.
2026-04-05 — Section 6 "Third-Party RBAC Ownership" amended with RBACProfile authorship
  invariant. compiler component (conductor-schema.md §16) is the exclusive authorship
  path for third-party RBACProfiles. Guardian enforces declarations; it never generates
  them. Seam operator RBACProfiles produced by compiler enable as part of bootstrap
  bundle. Third-party components without a Guardian-provisioned RBACProfile may not
  operate in a Guardian-governed cluster.

2026-04-05 — Guardian dual-role model locked. §1 Deployment boundary updated: Guardian
  is a single binary with two declared roles (management/tenant); role=tenant is optional
  per tenant via ClusterPack through Wrapper; Platform never deploys Guardian. §3 Two-Phase
  Boot superseded by §3 Management Cluster Boot Sequence: CNPG is pre-provisioned by
  compiler enable phase 0; Guardian startup migration runner connects before registering
  any controller; CNPGUnreachable condition on failure, degraded hold, no crash; three-step
  startup sequence (migration runner → bootstrap RBAC → controller registration). §15
  Guardian Role Model added (locked invariant): GUARDIAN_ROLE env var (management/tenant);
  absent/invalid causes structured exit; tenant role=management = sovereign mode (independent
  CNPG, no audit forwarding, no management Guardian relationship unless explicit
  federated-downstream IdentityProvider); management Guardian never assumes tenant topology;
  controller sets role-gated (management adds AuditSinkReconciler, tenant adds
  AuditForwarderController); PermissionService gRPC runs in both roles. §16 CNPG Deployment
  Contract added (locked invariant): management CNPG owned by compiler enable phase 0; tenant
  CNPG owned by ClusterPack; no other operator has CNPG dependency (INV-016); F-P8 recorded.

2026-04-09 — G-BL-11: Tenant Guardian CNPG and audit forwarding model amended. §15
  Role=tenant updated: tenant Guardian always connects to tenant-local CNPG (no CRD-only
  mode; full persistence parity with role=management). Audit forwarding changed from
  default-on to opt-in: GUARDIAN_AUDIT_FORWARD env var (default: false) is the sole
  control. GUARDIAN_AUDIT_FORWARD=false = sovereign mode (independent CNPG, independent
  identity plane, no forwarding; the default). GUARDIAN_AUDIT_FORWARD=true = federated
  mode (tenant Guardian forwards audit events to management Guardian via Conductor
  federation channel; Conductor is the transport, tenant is the producer, management is
  the consumer). Sovereign mode is no longer tied to role=management on a tenant cluster
  — it is the default state of every role=tenant Guardian. Controller set table expanded
  to three columns reflecting the GUARDIAN_AUDIT_FORWARD axis: AuditForwarderController
  activates only when GUARDIAN_AUDIT_FORWARD=true. PermissionService paragraph updated
  to reference federated-mode tenants rather than "non-sovereign" tenants.
