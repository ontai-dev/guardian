# guardian-schema
> API Group: security.ontai.dev
> Operator: guardian
> All agents absorb this document. Security is platform-wide.

---

## 1. Domain Boundary

guardian owns all RBAC across the entire platform - management cluster and
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
Guardian is a single binary with two declared deployment roles - see §15 Guardian Role
Model for the complete contract. Role=management is deployed on the management cluster
by compiler enable. Role=tenant is optionally deployed on tenant clusters exclusively
via ClusterPack through Wrapper. Platform never deploys Guardian and never assumes
Guardian is present on any target cluster.

On target clusters without a Guardian ClusterPack: the security plane responsibilities
- admission webhook, PermissionSnapshot receipt, local PermissionService, RBAC
enforcement - are hosted exclusively by the conductor Deployment in ont-system. This
is the default model for all target clusters.

On target clusters running a Guardian ClusterPack (role=tenant or role=management):
Guardian runs alongside Conductor. The role determines which controller sets register
and whether the tenant's security plane is federated with or sovereign from the
management Guardian. Conductor continues to own the admission webhook and
PermissionSnapshotReceipt on all target clusters regardless of Guardian presence.

---

## 2. Namespace Placement

| Resource                                              | Namespace                                                                     |
|-------------------------------------------------------|-------------------------------------------------------------------------------|
| RBACPolicy (management fleet, compiler-created)       | seam-system -- canonical name `management-policy`                             |
| PermissionSet (management ceiling, compiler-created)  | seam-system -- canonical name `management-maximum`                            |
| RBACProfile (Seam operators)                          | seam-system on management cluster; ont-system on tenant cluster               |
| RBACPolicy (cluster-level, guardian-created)          | seam-tenant-{clusterName} -- canonical name `cluster-policy`                  |
| PermissionSet (cluster ceiling, guardian-created)     | seam-tenant-{clusterName} -- canonical name `cluster-maximum`                 |
| RBACProfile (all non-seam-operator components)        | seam-tenant-{clusterName} -- all third-party, pack, and non-seam components   |
| IdentityBinding                                       | tenant namespace                                                              |
| PermissionSnapshot                                    | seam-system (internal to guardian)                                            |
| CNPG cluster                                          | seam-system                                                                   |
| PermissionSnapshotReceipt                             | ont-system on target cluster                                                  |

**Canonical name contract:** The names `management-policy`, `management-maximum`,
`cluster-policy`, and `cluster-maximum` are platform constants. Compiler uses
`management-policy`/`management-maximum`. Guardian's ClusterRBACPolicyReconciler
uses `cluster-policy`/`cluster-maximum`. No other names are valid for these objects.

**RBACPolicy authorship rule (invariant):**
RBACPolicy is never human-authored. Compiler authors `management-policy` as part of
the bootstrap/enable bundle. Guardian's ClusterRBACPolicyReconciler authors one
`cluster-policy` per cluster when InfrastructureTalosCluster is admitted. These are
the only two authorship paths. No other controller or human may create an RBACPolicy.

**Seam operator RBACProfile placement:**
Seam operator profiles (guardian, platform, wrapper, conductor, seam-core) are created
by compiler enable as part of the management cluster bootstrap bundle. On the management
cluster they live in seam-system and reference `management-policy`. On tenant clusters
they live in ont-system and reference that tenant cluster's `cluster-policy`.

**All other component RBACProfile placement:**
Every component that is not a Seam operator -- third-party tools (cert-manager, kueue,
metallb), pack components, and any future additions -- has its RBACProfile in
`seam-tenant-{clusterName}` referencing that cluster's `cluster-policy`. The actual
Kubernetes RBAC resources (Roles, ClusterRoles, RoleBindings) for these components
live in their operational namespaces as before. Only the governance record (RBACProfile)
moves to seam-tenant-{clusterName}. There are no per-component RBACPolicy objects and
no per-component PermissionSet objects. The cluster-maximum PermissionSet is the sole
ceiling for all components on that cluster.

**RBACProfileReconciler same-namespace constraint:**
The governing RBACPolicy must be in the same namespace as the RBACProfile. This
constraint is satisfied by design: seam operator profiles in seam-system reference
`management-policy` in seam-system; all other profiles in seam-tenant-{clusterName}
reference `cluster-policy` in seam-tenant-{clusterName}.

**seam-tenant-{clusterName} namespace lifecycle:**
ClusterRBACPolicyReconciler (role=management only) creates `cluster-maximum`
PermissionSet and `cluster-policy` RBACPolicy when InfrastructureTalosCluster is
admitted. When the TalosCluster CR is deleted, the reconciler cascades deletion of
all RBACProfiles labeled `ontai.dev/policy-type=component` in the namespace, then
`cluster-maximum` and `cluster-policy`, then removes its finalizer from the
TalosCluster. Cross-namespace ownerReferences are prohibited by Kubernetes; the
finalizer pattern is the authoritative lifecycle coupling (see §18 and §19).

---

## 3. Management Cluster Boot Sequence

**This section supersedes the former Two-Phase Boot model as of 2026-04-05.**

Guardian on the management cluster starts after CNPG is already operational.
Compiler enable phase 0 (00-infrastructure-dependencies) provisions the CNPG operator
and CNPG Cluster CR before Guardian is deployed - see §16 CNPG Deployment Contract and
conductor-schema.md §9 for the six-phase enable bundle structure.

**Guardian startup sequence (management cluster, role=management):**

**Step 1 - Migration runner:**
Before registering any controller, Guardian's startup migration runner connects to the
CNPG instance and applies all pending schema migrations in order. If CNPG is unreachable
at startup, Guardian emits a `CNPGUnreachable` condition on its singleton status CR and
holds in degraded state - all controller reconciliation is suspended, no crash occurs.
Guardian recovers automatically when CNPG becomes reachable and the migration runner
completes successfully. This is the only blocking gate before controller registration.

**Step 2 - Bootstrap annotation sweep and third-party profile creation:**
After the migration runner completes, the bootstrap annotation sweep runnable starts.
It runs in two phases:

Phase 2a - Annotation sweep: All pre-existing RBAC resources (Roles, RoleBindings,
ClusterRoles, ClusterRoleBindings, ServiceAccounts) across all non-exempt namespaces
are stamped with `ontai.dev/rbac-owner=guardian` and
`ontai.dev/rbac-enforcement-mode=audit`. This phase runs in audit mode -- RBAC changes
are logged but not rejected. kube-system is always skipped. The sweep is idempotent.

Phase 2b - Third-party profile creation: Immediately after the sweep completes,
Guardian creates baseline PermissionSet, RBACPolicy, and RBACProfile for each
third-party component whose namespace exists on the cluster. Resources are created
in the component's canonical namespace (cert-manager, kueue-system,
metallb-system, local-path-storage). Cilium is excluded -- kube-system is
sweep-exempt. If a component namespace is absent, that component is skipped silently.
This creation is idempotent -- existing resources are left unchanged.

Once both phases complete, `SweepDone` is set to true.

**Step 3 - Controller registration and enforcement mode transition:**
All role-gated controllers register (see §15 for the role=management controller set).
The admission webhook becomes operational. The bootstrap RBAC window closes.

BootstrapController monitors all RBACProfiles across all namespaces. Once all
profiles (Seam operator profiles in seam-system plus third-party profiles in their
component namespaces) reach `provisioned=true`, WebhookMode advances:
Initialising -> ObserveOnly -> Enforcing.

In Enforcing mode, any RBAC resource created or updated without
`ontai.dev/rbac-owner=guardian` is rejected at admission. All RBAC changes must go
through Guardian. The only path for a third-party component to change its RBAC
after this point is through an updated RBACProfile.

If the management cluster is rebuilt, all three steps re-execute in order. The migration
runner is idempotent - it applies only unapplied migrations and is safe to re-run.

---

## 4. Bootstrap RBAC Window

Before guardian's admission webhook is operational on the management cluster,
the conductor enable phase must apply RBAC to install guardian itself. This
window is explicitly declared in the enable phase protocol. The bootstrap RBACPolicy
in git defines exactly what is permitted in this window. As soon as guardian's
webhook becomes operational, the window closes permanently. RBAC applied in this
window is immediately reconciled by guardian on startup - validated and
ownership-annotated if compliant, flagged for remediation if not. INV-020.

On target clusters, the bootstrap RBAC window is handled differently: the conductor
Deployment arrives via the agent ClusterPack deployment. Once the conductor starts
on a target cluster, its admission webhook is immediately operational. There is no
bootstrap RBAC window on target clusters - the agent pack is applied via the
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
management cluster is temporarily unreachable - the conductor serves decisions
from its local acknowledged snapshot state.

The webhook behavior is identical on management and target clusters: any RBAC
resource lacking the `ontai.dev/rbac-owner=guardian` annotation is rejected.

**Tenant cluster bootstrap sweep (Conductor role=tenant):**
Conductor role=tenant mirrors this enforcement model independently. On leader
election it runs `TenantBootstrapSweep` in two phases:

Phase 1 (annotation sweep): stamps `ontai.dev/rbac-owner=guardian` on all
pre-existing RBAC resources (Role, ClusterRole, RoleBinding, ClusterRoleBinding,
ServiceAccount) using the same annotation constants as Guardian. Enforcement mode
during this phase is audit -- resources lacking the annotation are logged but
admitted.

Phase 2 (profile creation): creates PermissionSet, RBACPolicy, and RBACProfile
for each component in its known catalog (cert-manager, kueue, cnpg, metallb,
local-path-provisioner) via the dynamic client in the component's canonical namespace.
Components whose namespace is absent are skipped and retried on the next periodic
run. If Guardian's security CRDs are not installed on the tenant cluster, the profile
creation phase is skipped entirely and the enforcement gate remains in audit mode.

After both phases complete, the `EnforcementGate` transitions to strict mode and
the admission webhook at `/validate/rbac-ownership` begins rejecting unannotated
RBAC resources. The sweep repeats every 5 minutes so newly deployed Helm charts are
picked up without restart.

Annotation constants (`ontai.dev/rbac-owner=guardian`) are defined in both Guardian
and Conductor independently -- Conductor does not import Guardian internal packages.
Both use identical string literals. CS-INV-001, conductor-schema.md §15.

---

## 6. Third-Party RBAC Ownership

**LOCKED INVARIANT (partial) - Platform Governor directive 2026-04-05: RBACProfile authorship.**

guardian wraps third-party component RBAC - CNPG, cert-manager, Kueue, metallb,
and future components - into RBACProfiles with ownership annotations.

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

**RBACProfile authorship - automatic bootstrap creation:**
Guardian automatically creates baseline PermissionSet, RBACPolicy, and RBACProfile
for known third-party components (cert-manager, kueue, CNPG, metallb,
local-path-provisioner) as part of Phase 2b of the bootstrap sequence. Resources are
created in the component's canonical namespace immediately after the annotation sweep
completes and before SweepDone is set. This is Guardian's authoritative bootstrap
path for its known component catalog.

Baseline PermissionSets grant broad access (`*/*` with all standard verbs) during
the bootstrap phase. Post-bootstrap, operators may submit updated RBACProfiles with
tighter PermissionSets to reduce to least-privilege.

For components not in Guardian's static catalog, `compiler component` remains the
authorship path. See conductor-schema.md §16.

**Enforcement boundary:**
During the annotation sweep (Phase 2a), enforcement mode is audit: RBAC changes
are logged but not rejected. Once all third-party profiles reach Provisioned=True
and WebhookMode advances to Enforcing, any RBAC resource created or updated without
`ontai.dev/rbac-owner=guardian` is rejected at admission. The only path for a
component to change its RBAC after this point is through an updated RBACProfile
submitted to Guardian.

**Seam operator RBACProfiles:**
The first-class platform-owned RBACProfiles for Seam operator service accounts
(Guardian, Platform, Wrapper, Conductor, seam-core) are produced by `compiler enable`
as part of the management cluster bootstrap bundle and never modified at runtime.

**Pack component RBAC intake flow (Governor-approved 2026-04-25):**
When a ClusterPack is compiled, it produces an OCI artifact that includes an RBAC
layer (Kubernetes Role/ClusterRole/RoleBinding/ClusterRoleBinding manifests) and
a declared permission profile for the component. Guardian intake handles the RBAC
layer; conductor (role=tenant) handles the same on tenant clusters. The intake
creates exactly one governance object per component in `seam-tenant-{targetCluster}`:

RBACProfile named `{componentName}` -- the component's governance entry with:
- `rbacPolicyRef: cluster-policy` -- references the cluster-level RBACPolicy
- `permissionDeclarations` -- the component's specific permission claim declared
  inline (no separate PermissionSet object per component)
- Labels: `ontai.dev/managed-by=guardian`, `ontai.dev/policy-type=component`

There are no per-component RBACPolicy objects and no per-component PermissionSet
objects. The cluster-maximum PermissionSet is the sole governance ceiling; component
permission claims live in RBACProfile.permissionDeclarations.

The intake guard: if `cluster-policy` does not yet exist in `seam-tenant-{targetCluster}`,
the intake handler returns an error and the caller retries. ClusterRBACPolicyReconciler
(§18, §19) must run before any component RBAC can be registered.

On ClusterPack deletion or TalosCluster deletion: ClusterRBACPolicyReconciler cascades
deletion of all RBACProfiles labeled `ontai.dev/policy-type=component` in
`seam-tenant-{clusterName}`, eliminating orphaned governance records. The actual
Kubernetes RBAC resources (Roles etc.) in operational namespaces are cleaned up by
the pack-delete flow independently.

---

## 7. CRDs - Management Cluster

### RBACPolicy

Scope: Namespaced. seam-system for Layer 1 (management-policy). seam-tenant-{clusterName}
for Layer 2 (cluster-policy). See §19 for the authoritative placement rules.
Short name: rp

Governing policy that constrains what RBACProfiles within its scope may declare.
Profiles that exceed their governing policy are rejected at admission.

management-policy is compiler-created and committed to git as part of the enable
bundle. cluster-policy is guardian-created by ClusterRBACPolicyReconciler when
InfrastructureTalosCluster is admitted. Neither is human-authored.

Key spec fields: subjectScope, allowedClusters, maximumPermissionSetRef,
enforcementMode (strict or audit).

---

### RBACProfile

Scope: Namespaced. seam-system/ont-system for seam operator profiles. seam-tenant-{clusterName}
for all other component profiles. See §19 for the authoritative placement rules.
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

Scope: Namespaced - seam-system.
Short name: idp

Declares an external identity source whose assertions Guardian will recognize and
validate. This is distinct from IdentityBinding: IdentityProvider configures the
upstream source - SSO provider, PKI certificate authority, token issuer, OIDC
endpoint - while IdentityBinding maps a specific identity from that source to a
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

Scope: Namespaced. seam-system for management-maximum. seam-tenant-{clusterName}
for cluster-maximum. See §19 for the authoritative placement rules.
Short name: ps

Named permission collection used as governance ceiling by RBACPolicy. management-maximum
is compiler-created alongside management-policy. cluster-maximum is guardian-created
alongside cluster-policy for each TalosCluster. There are no per-component PermissionSet
objects. Component permission claims are declared inline in RBACProfile.permissionDeclarations.
Key spec fields: permissions (API group, resource, verbs), description.

---

### PermissionSnapshot

Scope: Namespaced - seam-system. Internal to guardian.
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

## 8. CRDs - Target Cluster (conductor Managed)

All CRDs in this section are created and maintained exclusively by the conductor
Deployment in ont-system on the target cluster. No separate guardian agent
exists on target clusters. conductor incorporates all target cluster security plane
responsibilities.

### PermissionSnapshotReceipt

Scope: Namespaced - ont-system on target cluster.
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
of the acknowledged snapshot - it does not compute the EPG. EPG computation is
exclusively a management cluster function in the guardian controller.

PermissionService is the planned QuantAI integration point for AI-proposed
infrastructure operations requiring human gate review.

---

## 11. Execution Gatekeeper

All four conditions must pass before PackExecution is admitted to Kueue. Enforced
by guardian's admission webhook on the management cluster - a hard block, not
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

NetworkPolicy restricts ingress to seam-system to guardian pods only.
CNPG credentials are Secrets in seam-system with no RBAC bindings for human
users - not even cluster-admin can read them through normal paths.
Audit access for the security team is granted through a designated read-only view
exposed by guardian's PermissionService - never through direct database access.

---

## 14. Cross-Domain Rules

Reads: platform.ontai.dev/QueueProfile to provision Kueue ClusterQueue resources.
Reads: infrastructure.ontai.dev/InfrastructureTalosCluster to detect new cluster registrations and
  create initial RBACProfiles.
Reads: infrastructure.ontai.dev/InfrastructureRunnerConfig status (capability confirmation).
Intercepts: infrastructure.ontai.dev/InfrastructurePackExecution at admission (execution gatekeeper).
Writes: security.ontai.dev resources on management cluster.
Writes: PermissionSnapshotReceipt on target clusters via conductor.
Writes: Kueue ClusterQueue and ResourceFlavor resources (derived from QueueProfile).
Never writes to platform.ontai.dev or infrastructure.ontai.dev CRDs.

The signing annotation (ontai.dev/snapshot-signature) on PermissionSnapshot is
written by the management cluster conductor, not by the guardian controller.
The controller generates the snapshot. The agent signs it. These are sequential,
not concurrent writes.

---

## 15. Guardian Role Model

**LOCKED INVARIANT - Platform Governor directive 2026-04-05.**

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
role=tenant - full persistence parity with role=management is the only supported
configuration. The tenant Guardian registers a reduced controller set. Audit forwarding
to the management Guardian is opt-in, controlled exclusively by the
`GUARDIAN_AUDIT_FORWARD` environment variable (default: `false`). Tenant Guardian is
sovereign by default.

**GUARDIAN_AUDIT_FORWARD env var:**
Controls whether the tenant Guardian forwards audit events to the management Guardian.
Injected alongside `GUARDIAN_ROLE` in the Guardian Deployment spec. Only valid for
role=tenant; absent for role=management. Any value other than `true` or `false` causes
an immediate structured exit before controller initialisation. Valid values:

- `false` (default) - **Sovereign mode.** The tenant Guardian is fully sovereign:
  independent CNPG instance, independent identity plane, no audit forwarding to the
  management Guardian, no participation in the cross-cluster audit chain. The management
  Guardian has no knowledge of and no dependency on any tenant Guardian in this mode.
- `true` - **Federated mode.** The tenant Guardian forwards audit events to the
  management Guardian via the Conductor federation channel. Conductor is the transport:
  the tenant Guardian is the audit producer, the management Guardian is the audit
  consumer. The management Guardian processes forwarded events through its AuditSink
  pipeline. The tenant Guardian's AuditForwarderController activates in this mode only.

`GUARDIAN_AUDIT_FORWARD` is a Guardian concern only and has no effect on the Conductor
federation channel. The tenant Conductor connects to the management Conductor for
RunnerConfig validation regardless of Guardian topology. A cross-cluster identity trust
relationship between a tenant Guardian and the management Guardian is established only by
an explicit `federated-downstream` IdentityProvider CR authored by a human - never by
Guardian inference.

**Controller sets registered at startup, gated by role:**

| Controller                    | role=management | role=tenant (GUARDIAN_AUDIT_FORWARD=false) | role=tenant (GUARDIAN_AUDIT_FORWARD=true) |
|-------------------------------|-----------------|-------------------------------------------|------------------------------------------|
| PolicyReconciler              | ✓               | ✓                                         | ✓                                        |
| ProfileReconciler             | ✓               | ✓                                         | ✓                                        |
| IdentityProviderReconciler    | ✓               | ✓                                         | ✓                                        |
| IdentityBindingReconciler     | ✓               | ✓                                         | ✓                                        |
| ClusterRBACPolicyReconciler   | ✓               | -                                         | -                                        |
| AuditSinkReconciler           | ✓               | -                                         | -                                        |
| AuditForwarderController      | -               | -                                         | ✓                                        |

PermissionService gRPC runs in both roles. The management Guardian serves authorization
decisions for the management cluster and all tenant Guardians operating in federated mode
(GUARDIAN_AUDIT_FORWARD=true) that forward audit events to it. The tenant Guardian
(role=tenant) serves decisions for its own cluster locally - this supplements, but does
not replace, the Conductor local PermissionService.

This is a locked invariant. The role gating on controller registration is permanent.
Adding a controller to a role that does not include it requires a Platform Governor
constitutional amendment.

---

## 16. CNPG Deployment Contract

**LOCKED INVARIANT - Platform Governor directive 2026-04-05.**

**Management cluster:**
The CNPG operator and CNPG Cluster CR are provisioned by compiler enable as a dedicated
phase 0 of the enable bundle (`00-infrastructure-dependencies`) - before Guardian is
deployed. See conductor-schema.md §9 for the six-phase enable bundle structure. Guardian's
startup migration runner (§3 Step 1) connects to CNPG and applies pending schema
migrations before registering any controller. If CNPG is unreachable at Guardian startup,
Guardian emits a `CNPGUnreachable` condition on its singleton status CR and holds in
degraded state - controller reconciliation is suspended, no crash occurs. Guardian
recovers automatically when CNPG becomes reachable and the migration runner completes.

The CNPG deployment on the management cluster is owned exclusively by compiler enable.
No operator writes CNPG resources on the management cluster. Human review of the enable
bundle must verify phase 0 contents before GitOps application.

**Tenant clusters:**
CNPG on a tenant cluster is provisioned via ClusterPack through Wrapper. It is part of
the Guardian tenant deployment pack - a pack the tenant opts into by creating the
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

---

## 17. Audit Record Schema

Guardian writes audit events to the CNPG audit_events table via `AuditWriter`
(database package). The record type is `database.AuditEvent`. This section
specifies the canonical field contract for that type.

### AuditEvent fields

| Field          | Type   | Description                                                                   |
|----------------|--------|-------------------------------------------------------------------------------|
| ClusterID      | string | Identifier of the cluster where the event originated.                         |
| SequenceNumber | int64  | Monotonic event sequence number. Used for deduplication.                      |
| Subject        | string | Identity of the principal performing the action.                              |
| Action         | string | Dot-namespaced event type (e.g., rbac.wrapped, bootstrap.annotation_sweep).   |
| Resource       | string | Name of the resource the action targets.                                      |
| Decision       | string | Authorization decision: admit or deny.                                        |
| MatchedPolicy  | string | Name of the RBACPolicy or rule that produced the decision. Optional.          |
| LineageIndexRef| object | Reference to the InfrastructureLineageIndex governing the root declaration associated with this event. Optional -- absent for platform-wide events not associated with a specific root declaration. |

### lineageIndexRef

| Field     | Type   | Description                                   |
|-----------|--------|-----------------------------------------------|
| Name      | string | Name of the InfrastructureLineageIndex CR.    |
| Namespace | string | Namespace of the InfrastructureLineageIndex CR. |

**Population rule:** Guardian reconcilers populate LineageIndexRef when emitting
audit events for governed objects (RBACProfile provisioned, PermissionSnapshot
drift, IdentityBinding resolved). Platform-wide events (bootstrap annotation sweep,
startup migration complete) leave LineageIndexRef absent. This is not an error --
absent lineageIndexRef signals a platform-wide event, not an object-scoped event.

**Correlation contract:** When LineageIndexRef is present, the combination
(ClusterID, SequenceNumber, LineageIndexRef.Name, LineageIndexRef.Namespace)
uniquely identifies the event within the causal chain of the root declaration
recorded in the InfrastructureLineageIndex. Vortex uses this to correlate audit
events with lineage records without additional lookups.

---

## 18. ClusterRBACPolicyReconciler

**Role gate:** role=management only. Never runs on role=tenant instances.

**Watches:** `infrastructure.ontai.dev/v1alpha1/InfrastructureTalosCluster` (seam-system namespace).
Guardian imports seam-core's `seamv1alpha1` package to watch this type -- Decision G.
Also watches changes to `management-maximum` PermissionSet in seam-system and re-queues
all TalosCluster CRs when it changes (so cluster-maximum re-validation runs).

**Purpose:** For every InfrastructureTalosCluster, maintain exactly one cluster-level
RBACPolicy (`cluster-policy`) and its governance ceiling PermissionSet (`cluster-maximum`)
in the `seam-tenant-{clusterName}` namespace. See §19 for the full three-layer hierarchy.

**Finalizer:** `security.ontai.dev/cluster-rbac` placed on the TalosCluster CR.

**On creation (or reconcile when cluster-policy absent):**
1. Read `management-maximum` PermissionSet from seam-system. Validate that the cluster
   PermissionSet to be created is a subset of the management ceiling. This is the
   functional obligation check -- option (a), at creation time, not at admission.
   No deadlock: management-maximum is compiler-created and exists before guardian starts.
2. Create PermissionSet `cluster-maximum` in `seam-tenant-{clusterName}`:
   - Labels: `ontai.dev/managed-by=guardian`, `ontai.dev/policy-type=cluster`
   - Spec.permissions: initially broad ceiling; tightened post-bootstrap by operator.
3. Create RBACPolicy `cluster-policy` in `seam-tenant-{clusterName}`:
   - Labels: `ontai.dev/managed-by=guardian`, `ontai.dev/policy-type=cluster`
   - Spec.subjectScope: tenant
   - Spec.allowedClusters: [{clusterName}]
   - Spec.maximumPermissionSetRef: cluster-maximum
   - Spec.enforcementMode: audit (initial; promoted to strict post-bootstrap)
4. Add finalizer `security.ontai.dev/cluster-rbac` to the TalosCluster CR.

All steps are idempotent. A second reconcile that finds both objects already present
re-runs the validation check but performs no writes if objects are unchanged.

**On deletion (TalosCluster DeletionTimestamp set):**
1. List and delete all RBACProfiles in `seam-tenant-{clusterName}` labeled
   `ontai.dev/policy-type=component` (all non-seam-operator component profiles).
2. Delete PermissionSet `cluster-maximum` in `seam-tenant-{clusterName}`.
3. Delete RBACPolicy `cluster-policy` in `seam-tenant-{clusterName}`.
4. Remove finalizer `security.ontai.dev/cluster-rbac` from TalosCluster.

Steps 2 and 3 run after step 1 completes. Step 4 runs after steps 2 and 3 complete.

**Cross-namespace constraint:**
TalosCluster lives in seam-system. Cluster RBAC objects live in seam-tenant-*.
Kubernetes prohibits ownerReferences across namespaces. The finalizer pattern on
TalosCluster is the authoritative lifecycle coupling. No ownerReference is set on
cluster-policy or cluster-maximum pointing to TalosCluster.

**Label constants:**
- `ontai.dev/managed-by`: value `guardian`
- `ontai.dev/policy-type`: value `cluster` for cluster-level objects, `component` for all other component profiles

## 19. Three-Layer RBAC Hierarchy

This section is the authoritative structural specification for the ONT RBAC governance
model. It supersedes any per-section descriptions that conflict with it.

---

### Layer 1 - Management RBACPolicy (fleet ceiling)

**Object:** `management-policy` (RBACPolicy) in seam-system.
**Object:** `management-maximum` (PermissionSet) in seam-system.
**Authorship:** compiler exclusively, as part of the bootstrap/enable bundle.
  Never created or modified by guardian's reconcilers.

`management-policy` governs the entire fleet. It references `management-maximum`
as its ceiling PermissionSet. Without guardian sweeping and taking governance
ownership of this policy on startup, it is inert. Guardian gives it enforcement
meaning through the bootstrap annotation sweep and webhook enforcement chain.

**Who references Layer 1:**
Seam operator RBACProfiles (guardian, platform, wrapper, conductor, seam-core).
On the management cluster these profiles live in seam-system. On tenant clusters
they live in ont-system. In both cases `rbacPolicyRef: management-policy`.

Layer 1 is the fleet authority. Any operation that spans clusters or authorizes
fleet management actions must be governed by Layer 1.

---

### Layer 2 - Cluster RBACPolicy (per TalosCluster)

**Object:** `cluster-policy` (RBACPolicy) in seam-tenant-{clusterName}.
**Object:** `cluster-maximum` (PermissionSet) in seam-tenant-{clusterName}.
**Authorship:** guardian's ClusterRBACPolicyReconciler (role=management only).
  Never human-authored.

One cluster-policy per TalosCluster. Created when InfrastructureTalosCluster is
admitted to seam-system. The cluster PermissionSet (`cluster-maximum`) is the sole
governance ceiling for all non-seam-operator components on that cluster. There are
no per-component RBACPolicy objects and no per-component PermissionSet objects.

**Functional obligation to Layer 1:**
At cluster-policy creation time, ClusterRBACPolicyReconciler reads `management-maximum`
from seam-system and validates that `cluster-maximum` is a subset of it. This is
option (a) -- creation-time validation, not admission-time. The deadlock-free guarantee:
management-maximum is compiler-created and guaranteed to exist before guardian starts;
the reconciler only runs after guardian is up. Re-validation occurs whenever
management-maximum changes.

**Delivery to tenant clusters:**
`cluster-maximum` PermissionSet is included in the signed PermissionSnapshot
delivered from the management cluster to the tenant cluster. Conductor (role=tenant)
verifies the guardian signature and reconciles the PermissionSet before permitting
any cluster operations. The PermissionSet on a tenant cluster is a signed, delivered
artifact -- never locally authored.

**Management cluster special case:**
The management cluster (ccs-mgmt) holds both Layer 1 (`management-policy` for
fleet-wide authority) and Layer 2 (`cluster-policy` in seam-tenant-ccs-mgmt, created
when InfrastructureTalosCluster for ccs-mgmt is admitted). This is because ccs-mgmt
is also a seam tenant. Fleet-wide operations are governed by Layer 1. Operations
scoped to the ccs-mgmt cluster are governed by Layer 2 for ccs-mgmt.

---

### Layer 3 - Component RBACProfiles

**Seam operator profiles:**
- Location: seam-system (management cluster), ont-system (tenant cluster)
- rbacPolicyRef: management-policy (Layer 1)
- Created by compiler enable as part of the bootstrap bundle

**All other component profiles (third-party tools, pack components, seam-core on non-management clusters):**
- Location: seam-tenant-{clusterName}
- rbacPolicyRef: cluster-policy (Layer 2)
- Created by guardian intake flow (management cluster) or conductor role=tenant sweep (tenant cluster)
- No separate PermissionSet object per component; permission claims are declared
  inline via RBACProfile.permissionDeclarations
- Label: `ontai.dev/policy-type=component`

**IdentityProvider / IdentityBinding chain:**
IdentityProvider declares the upstream trust anchor (OIDC endpoint, PKI CA, token issuer).
IdentityBinding maps a specific identity from that provider to an ONT permission principal.
The principal is referenced by RBACProfile.principalRef. The governance chain is:

  IdentityProvider (trust anchor)
    -> IdentityBinding (identity to principal)
      -> RBACProfile.principalRef (principal to permissions)
        -> rbacPolicyRef: cluster-policy (Layer 2) or management-policy (Layer 1)

There is no direct IdentityProvider-to-RBACPolicy link. The link runs through the
principal resolved by IdentityBinding. Multiple RBACProfiles may reference the same
principal. Multiple IdentityBindings may reference the same IdentityProvider.

---

### No-deadlock guarantee

Guardian starts after compiler has applied Layer 1 (`management-policy`, `management-maximum`)
to seam-system. Layer 2 is created by the reconciler after guardian is up -- management-maximum
is guaranteed present. Layer 3 component profiles are admitted by the webhook after
cluster-policy exists. The admission webhook checks RBACProfile against cluster-policy only;
it never reads management-maximum at admission time. The subset check (cluster-maximum within
management-maximum) is strictly a reconciler-time operation, not an admission-time operation.
Bootstrap seam operator profiles are admitted during the bootstrap RBAC window before the
webhook enforces -- no deadlock at any startup phase.

---

## 20. Tenant Cluster Conductor Onboarding Protocol

This section specifies the two-site handshake that Platform and Guardian execute
together when a TalosCluster with mode=import, role=tenant is admitted. The result
of the protocol is a running Conductor agent on the tenant cluster that operates
under signed management authority.

---

### Participants

| Participant | Runs on | Responsibility |
|-------------|---------|----------------|
| Platform (TalosClusterReconciler) | management cluster | Remote infrastructure -- ont-system, SA, Deployment |
| Guardian (ClusterRBACPolicyReconciler) | management cluster | Management-side RBACProfile for tenant conductor |
| Conductor (role=tenant) | tenant cluster | Pull RBACProfile from management, write to ont-system |

---

### Protocol sequence

**Step 1 -- Management-side namespace and secrets (Platform)**
Platform creates `seam-tenant-{clusterName}` and copies the kubeconfig Secret into it.
See platform-schema.md §12 steps 1-2.

**Step 2 -- Guardian provisions conductor-tenant RBACProfile (Guardian)**
ClusterRBACPolicyReconciler creates a `conductor-tenant` RBACProfile in
`seam-tenant-{clusterName}` as part of its normal reconcile pass for any
role=tenant TalosCluster. This profile is the management-side authoritative
declaration for the tenant conductor's permissions.

Profile contract:
- Name: `conductor-tenant`
- Namespace: `seam-tenant-{clusterName}`
- Labels: `ontai.dev/managed-by=guardian`, `ontai.dev/policy-type=seam-operator`
- Spec.principalRef: `conductor`
- Spec.targetClusters: `[clusterName]`
- Spec.rbacPolicyRef: `cluster-policy` (Layer 2, same namespace)
- Spec.permissionDeclarations: `[{permissionSetRef: cluster-maximum, scope: cluster}]`

The `seam-operator` policy-type label distinguishes this profile from component
profiles. The component backfill runnable (GUARDIAN-BL-RBACPROFILE-SWEEP) does
not process seam-operator profiles. Deletion is handled explicitly by
reconcileDelete when the TalosCluster is removed, not by the component sweep.

**Step 3 -- Platform creates remote infrastructure (Platform)**
Platform's `EnsureConductorDeploymentOnTargetCluster` reads the import-path
kubeconfig (`target-cluster-kubeconfig` in `seam-tenant-{clusterName}`) and
connects to the tenant cluster. Using this remote connection it:
1. Creates the `ont-system` namespace if absent.
2. Creates the `conductor` ServiceAccount in `ont-system` if absent.
3. Creates the Conductor Deployment (role=tenant) in `ont-system` if absent.

The Deployment is built by `BuildConductorAgentDeployment` with `CONDUCTOR_ROLE=tenant`.
Platform does not write the `conductor-tenant` RBACProfile to the tenant cluster.
That step is performed by Conductor itself (step 4).

**Step 4 -- Tenant conductor pulls and writes RBACProfile (Conductor)**
Conductor role=tenant, once running, pulls the `conductor-tenant` RBACProfile from
`seam-tenant-{clusterName}` on the management cluster and writes it into `ont-system`
on the tenant cluster. This is the CONDUCTOR-BL-TENANT-ROLE-RBACPROFILE-DISTRIBUTION
implementation path. Management Conductor retains signing authority.

**Step 5 -- Platform observes Deployment availability and advances (Platform)**
Platform polls the Conductor Deployment for `Available=True` via the remote kubernetes
client. When Available=True, Platform sets `ConductorReady=True` and `Ready=True` on
the TalosCluster. The cluster is now fully operational under Seam governance.

---

### Readiness gate

Platform uses `ConductorReady=True` as the sole gate before setting `Ready=True` on
an import-mode tenant TalosCluster. The phase progression is:

```
Bootstrapped=False --> Bootstrapped=True (after management-side steps complete)
ConductorReady=False --> ConductorReady=True (after Conductor Deployment Available)
Ready=True (set together with ConductorReady=True)
```

Platform does NOT use a separate `phase` field. The Conditions slice is the authoritative
state carrier. `RequeueAfter` is set to the capiPollInterval (20s) during the conductor
availability wait.

---

### Invariants

- Guardian creates exactly one `conductor-tenant` RBACProfile per role=tenant TalosCluster.
- Platform creates exactly one Conductor Deployment per role=tenant import cluster.
- The Deployment is stamped CONDUCTOR_ROLE=tenant. Any other value is a programming error.
- When the TalosCluster is deleted, Guardian deletes the `conductor-tenant` RBACProfile
  in reconcileDelete. Platform deletes the remote infrastructure through the normal
  controller-runtime GC path (ownerReference on seam-tenant-* resources) or teardown
  sequence (Decision H).
- The full PermissionSnapshotReceipt gRPC ceremony is future work
  (CONDUCTOR-BL-TENANT-ROLE-RBACPROFILE-DISTRIBUTION). The current readiness gate is
  Deployment Available=True, not gRPC handshake completion.

---

*security.ontai.dev schema - guardian*
*Amendments appended below with date and rationale.*

2026-03-30 - Target cluster security plane responsibilities transferred to conductor.
  No separate guardian Deployment on target clusters. conductor hosts admission
  webhook, PermissionSnapshotReceipt management, local PermissionService, and drift
  detection on target clusters. Cryptographic signing model added: management cluster
  conductor signs PermissionSnapshot; target cluster conductor verifies before
  acknowledgement. Section 1 domain boundary clarified. Section 5 admission webhook
  updated for two-context model. Section 8 receipt management updated to name conductor
  explicitly. Section 10 PermissionService split into management and target context.
  INV-026 referenced.

2026-04-03 - IdentityProvider CRD added to Section 7. Relationship to IdentityBinding
  formally specified. IdentityProvider is the upstream trust anchor. IdentityBinding is
  the principal assignment. An IdentityBinding without a matching IdentityProvider for
  its identityType is rejected at admission. IdentityProvider is a prerequisite before
  any Controller Engineer session implementing identity trust methods in IdentityBinding.
2026-04-05 - Section 6 "Third-Party RBAC Ownership" amended with RBACProfile authorship
  invariant. compiler component (conductor-schema.md §16) is the exclusive authorship
  path for third-party RBACProfiles. Guardian enforces declarations; it never generates
  them. Seam operator RBACProfiles produced by compiler enable as part of bootstrap
  bundle. Third-party components without a Guardian-provisioned RBACProfile may not
  operate in a Guardian-governed cluster.

2026-04-05 - Guardian dual-role model locked. §1 Deployment boundary updated: Guardian
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

2026-04-21 - lineageIndexRef added to audit record specification (§17 Audit Record
  Schema added). Guardian reconcilers populate this field when emitting audit events
  for governed objects. Platform-wide events leave lineageIndexRef absent. Closes the
  correlation loop between governance events and the structural lineage index.
  LineageIndexRef carries name and namespace of the InfrastructureLineageIndex CR
  governing the root declaration associated with the event. Session/12.

2026-04-09 - G-BL-11: Tenant Guardian CNPG and audit forwarding model amended. §15
  Role=tenant updated: tenant Guardian always connects to tenant-local CNPG (no CRD-only
  mode; full persistence parity with role=management). Audit forwarding changed from
  default-on to opt-in: GUARDIAN_AUDIT_FORWARD env var (default: false) is the sole
  control. GUARDIAN_AUDIT_FORWARD=false = sovereign mode (independent CNPG, independent
  identity plane, no forwarding; the default). GUARDIAN_AUDIT_FORWARD=true = federated
  mode (tenant Guardian forwards audit events to management Guardian via Conductor
  federation channel; Conductor is the transport, tenant is the producer, management is
  the consumer). Sovereign mode is no longer tied to role=management on a tenant cluster
  - it is the default state of every role=tent Guardian. Controller set table expanded
  to three columns reflecting the GUARDIAN_AUDIT_FORWARD axis: AuditForwarderController
  activates only when GUARDIAN_AUDIT_FORWARD=true. PermissionService paragraph updated
  to reference federated-mode tenants rather than "non-sovereign" tenants.

2026-04-25 - Three-Layer RBAC Hierarchy. Governor-approved architectural change.
  §2 namespace placement fully rewritten: two canonical policies (management-policy/
  management-maximum in seam-system; cluster-policy/cluster-maximum per seam-tenant-*);
  seam operator profiles in seam-system/ont-system referencing Layer 1; all other
  component profiles in seam-tenant-{clusterName} referencing Layer 2; no per-component
  RBACPolicy or per-component PermissionSet objects. §6 pack intake updated: one
  RBACProfile per component (inline permissionDeclarations, rbacPolicyRef=cluster-policy),
  no separate PermissionSet per component. §18 ClusterRBACPolicyReconciler updated:
  creation-time validation of cluster-maximum against management-maximum (no deadlock),
  deletion cascade covers only component-labeled RBACProfiles. §19 Three-Layer RBAC
  Hierarchy added as authoritative structural specification: Layer 1 (compiler-created
  fleet ceiling), Layer 2 (guardian-created per-cluster policy, functionally bound to
  Layer 1 at creation time), Layer 3 (component profiles, no per-component governance
  objects). No-deadlock guarantee documented. IdentityProvider/IdentityBinding chain
  specified. Management cluster dual-layer pattern documented. RBACPolicy authorship
  invariant: compiler for Layer 1, guardian reconciler for Layer 2, never human-authored.
  security-system namespace removed throughout (does not exist).

2026-04-26 - §20 Tenant Cluster Conductor Onboarding Protocol added. T-19 and T-19a
  implementation contract. Guardian (ClusterRBACPolicyReconciler) creates conductor-tenant
  RBACProfile in seam-tenant-{cluster} for every role=tenant TalosCluster -- this is the
  management-side authoritative profile. Platform creates remote infrastructure (ont-system,
  conductor SA, Conductor Deployment) on the tenant cluster using the import-path kubeconfig.
  Conductor role=tenant pulls the profile and writes it to ont-system. Platform gates
  Ready=True on ConductorReady=True (Deployment Available), not on gRPC handshake
  (CONDUCTOR-BL-TENANT-ROLE-RBACPROFILE-DISTRIBUTION is future). LabelValuePolicyTypeSeamOperator
  added as the policy-type discriminator for seam-operator profiles in seam-tenant-* namespaces.
