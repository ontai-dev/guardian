# guardian: Codebase Reference

## 1. Purpose

Guardian is the RBAC governance plane for all clusters in the ONT platform. It owns all RBAC resources on every cluster (CS-INV-001: admission webhook is the enforcement mechanism). It computes the Effective Permission Graph (EPG), delivers cryptographically signed PermissionSnapshots to target clusters, and writes an immutable audit trail via CNPG (CloudNativePG). Guardian does NOT own cluster lifecycle (platform), pack delivery (wrapper), or execution scheduling (conductor).

Two roles: `management` (full EPG, PermissionSet, AuditSink, ClusterRBACPolicyReconciler) and `tenant` (RBACProfile, IdentityBinding, IdentityProvider, AuditForwarder, TenantSnapshotRunnable, TenantProfileRunnable). Role resolved from `GUARDIAN_ROLE` env var at startup via `internal/role/role.go:40` `ParseRole()` and `ReadFromEnv()` L61.

---

## 2. Key Files and Locations

### API types (`api/v1alpha1/`)

| File | Size | Key types |
|------|------|-----------|
| `rbacprofile_types.go` | 173L | `RBACProfile` -- `principalRef`, `targetClusters`, `permissionDeclarations`, `rbacPolicyRef`; `status.provisioned` set only by RBACProfileReconciler (CS-INV-005) |
| `rbacpolicy_types.go` | 156L | `RBACPolicy` -- `subjectScope` (platform/tenant), `allowedClusters`, `maximumPermissionSetRef`, `enforcementMode` (strict/audit) |
| `permissionset_types.go` | 128L | `PermissionSet` -- list of `{APIGroups, Resources, Verbs}` tuples; ceiling for RBACPolicy |
| `permissionsnapshot_types.go` | 221L | `PermissionSnapshot` -- `subjects[]`, `principalPermissions[]`; `Fresh` condition gates PackExecution |
| `permissionsnapshotreceipt_types.go` | 93L | `PermissionSnapshotReceipt` -- written in `ont-system` on tenant by TenantSnapshotRunnable |
| `identitybinding_types.go` | 209L | `IdentityBinding` -- binds external identity to SeamMembership subject |
| `identityprovider_types.go` | 137L | `IdentityProvider` -- OIDC provider configuration |
| `guardian_types.go` | 133L | `Guardian` operator CR; `GuardianStatus` holds `WebhookMode`, `NamespaceEnforcements`, `Conditions`, and `DiscoveredAPIGroups` (third-party API groups added to management-maximum by APIGroupSweepController) |

No `ClusterRBACPolicy` or `ClusterAssignment` types exist in `api/v1alpha1/`. ClusterRBACPolicyReconciler watches seam-core `InfrastructureTalosCluster`, not a guardian-owned type.

### Controllers (`internal/controller/`)

| File | Key struct / function | Role | What it does |
|------|-----------------------|------|--------------|
| `rbacprofile_controller.go:47` | `RBACProfileReconciler` | both | 10-step reconcile (A-J). Step A: fetch. Step B (L109): deferred status patch setup. Step C (L118): advance ObservedGeneration. Step D: branch to `reconcileTenantSnapshotPath()` or management path. Steps E-J: ceiling validation, EPG recompute signal, RBAC provisioning via `provisionRBACResources()`. |
| `rbacprofile_controller.go:488` | `reconcileTenantSnapshotPath()` | both | Called when `spec.rbacPolicyRef` is empty. Checks for local PermissionSnapshot labeled `ontai.dev/snapshot-type=mirrored` in `ont-system`. If found, sets `Provisioned=true` without ceiling validation. Implements GUARDIAN-BL-RBACPROFILE-TENANT-PROVISIONING fix (guardian commit 693ba7d). |
| `rbacprofile_controller.go:572` | `provisionRBACResources()` | both | SSA-applies ServiceAccount, ClusterRole, ClusterRoleBinding for the profile's principal. |
| `rbacprofile_controller.go:629` | `resolvePermissionSetRules()` | both | Fetches PermissionSet, returns `[]rbacv1.PolicyRule`. |
| `rbacprofile_controller.go:440` | `MapPermissionSetToProfiles()` | both | Watch mapper: PermissionSet changes enqueue all RBACProfiles referencing it. |
| `cluster_rbacpolicy_controller.go:137` | `ClusterRBACPolicyReconciler.Reconcile()` | management | Watches `InfrastructureTalosCluster`; triggers on cluster create/delete. |
| `cluster_rbacpolicy_controller.go:158` | `reconcileCreate()` | management | Creates `cluster-maximum` PermissionSet + `cluster-policy` RBACPolicy in `seam-tenant-{cluster}`. Calls `ensureConductorTenantProfile()` at L256 to create `conductor-tenant` RBACProfile (guardian side of Decision C). |
| `cluster_rbacpolicy_controller.go:256` | `ensureConductorTenantProfile()` | management | Creates conductor-tenant RBACProfile in `seam-tenant-{cluster}` on management. Guardian side complete; conductor pull loop absent (CONDUCTOR-BL-TENANT-ROLE-RBACPROFILE-DISTRIBUTION). |
| `cluster_rbacpolicy_controller.go:290` | `reconcileDelete()` | management | Deletes cluster-policy, cluster-maximum, conductor-tenant in `seam-tenant-{cluster}`. |
| `epg_controller.go:101` | `EPGReconciler.Reconcile()` | management | Triggered by `ontai.dev/epg-recompute-requested` annotation. Reads all RBACProfiles + PermissionSets, calls `internal/epg/compute.go`, writes PermissionSnapshot CRs. |
| `epg_controller.go:367` | `reconcileDrift()` | management | Compares EPG output against live RBAC; sets DriftDetected. |
| `epg_controller.go:502` | `signalRecompute()` | management | Sets `ontai.dev/epg-recompute-requested` annotation on relevant CRs to trigger recompute. |
| `permissionset_controller.go:55` | `PermissionSetReconciler.Reconcile()` | management | Validates PermissionSet rules; sets Ready condition. |
| `permissionsnapshot_controller.go:73` | `PermissionSnapshotReconciler.Reconcile()` | both | Sets Fresh condition based on LastSigned/generation match. |
| `rbacpolicy_controller.go:63` | `RBACPolicyReconciler.Reconcile()` | both | Validates policy ceiling against management-maximum; sets Ready condition. |
| `identityprovider_controller.go:77` | `IdentityProviderReconciler.Reconcile()` | both | Checks OIDC discovery URL via `checkOIDCReachability()` L205. |
| `identitybinding_controller.go:60` | `IdentityBindingReconciler.Reconcile()` | both | Links external identity to IdentityProvider + SeamMembership. |
| `auditsink_controller.go:76` | `AuditSinkReconciler.Reconcile()` | management | Reads audit ConfigMaps, writes to CNPG `audit_events` via `processBatch()` L137. |
| `apigroup_sweep_controller.go:67` | `APIGroupSweepController.Reconcile()` | management | Watches CRDs; adds explicit `{apiGroups: [g], resources: ["*"]}` rules to `management-maximum` for every new third-party API group detected. Updates `Guardian.Status.DiscoveredAPIGroups`. guardian-schema.md §21. |
| `bootstrap_controller.go:126` | `BootstrapController.Reconcile()` | both | One-shot startup reconciler; closes bootstrap RBAC window when webhook is registered (CS-INV-004). |
| `tenant_snapshot_runnable.go:51` | `TenantSnapshotRunnable` | tenant | Pulls PermissionSnapshot from management cluster; writes local `PermissionSnapshotReceipt` in `Namespace`; upserts local mirror with label `ontai.dev/snapshot-type=mirrored` (const `LabelKeySnapshotType` L39, value `"mirrored"` L36); patches management PermissionSnapshot `status.lastAckedVersion`. |
| `tenant_profile_runnable.go:51` | `TenantProfileRunnable` | tenant | Creates RBACProfiles in `ont-system` on tenant for: cert-manager, kueue, cnpg, metallb, local-path-provisioner (catalog at `tenantKnownComponents` L22). No per-component PermissionSet or RBACPolicy (CS-INV-008). Each profile references `cluster-policy`. |

### Role and controller sets (`internal/role/`)

`ControllerSetForRole()` at `controllersets.go:37`:

- **Shared (both roles)**: RBACPolicyReconciler, RBACProfileReconciler, IdentityProviderReconciler, IdentityBindingReconciler, BootstrapController.
- **Management-only**: PermissionSetReconciler, EPGReconciler, AuditSinkReconciler, APIGroupSweepController.
- **Tenant-only**: AuditForwarderController.
- **Not in this function (started separately)**: PermissionService gRPC server (port 50051), TenantSnapshotRunnable, TenantProfileRunnable.

### Admission webhook (`internal/webhook/decision.go`)

`InterceptedKinds` at L24: `"Role"`, `"ClusterRole"`, `"RoleBinding"`, `"ClusterRoleBinding"`, `"ServiceAccount"`. **`"RBACProfile"` is NOT included** (T-25a open -- RBACProfile writes are not currently gated).

`AnnotationRBACOwner = "ontai.dev/rbac-owner"` (L16). `AnnotationRBACOwnerValue = "guardian"` (L17).

`BootstrapWindow` (L49): `atomic.Bool` that starts open. `NewBootstrapWindow()` L56 returns open window. Closed when webhook is registered (CS-INV-004).

### EPG (`internal/epg/`)

| File | Key function |
|------|-------------|
| `compute.go` | Main EPG computation: reads all provisioned RBACProfiles + PermissionSets, applies ceiling intersection, produces `principal -> permissions` map |
| `intersection.go` | Permission ceiling set intersection logic |
| `snapshot.go` | Converts EPG output into PermissionSnapshot CR fields |
| `types.go` | EPG-internal types |

### Permission service (`internal/permissionservice/`)

| File | Key symbols |
|------|-------------|
| `server.go:30` | `PermissionServiceServer` interface: `CheckPermission`, `ListPermissions`, `WhoCanDo`, `ExplainDecision` |
| `server.go:43` | gRPC service descriptor; FullMethod: `/ontai.security.v1alpha1.PermissionService/{Method}` |
| `service.go` | `PermissionServiceServerImpl` -- reads from in-memory `SnapshotStore` |
| `store.go` | `SnapshotStore` -- goroutine-safe cache of latest PermissionSnapshot per cluster |

### Database (`internal/database/`)

| File | What it does |
|------|-------------|
| `cnpg.go:28` | `DBClient` interface: `EventExists()` L69, `InsertEvent()` L81; table: `audit_events`; deduplication key: `(cluster_id, sequence_number)` |
| `audit_writer.go:36` | `SQLAuditWriter` -- writes events to `audit_events` via Postgres (CNPG) |
| `lazy.go` | `LazyDBClient` -- defers connection until first write (two-phase boot, CS-INV-003) |
| `secret.go` | Reads CNPG connection credentials from Kubernetes Secret |

CS-INV-002: CNPG is guardian-only. No other operator accesses the CNPG cluster in `seam-system`.

### Intake (`internal/intake/`)

Contains only `.gitkeep`. The `/rbac-intake/pack` HTTP endpoint called by conductor execute-mode is NOT implemented here. It is a placeholder for future intake routing logic.

---

## 3. Three-Layer RBAC Hierarchy (CS-INV-008)

- **Layer 1**: `management-maximum` PermissionSet + `management-policy` RBACPolicy in `seam-system`. Compiler-authored. Never human-authored.
- **Layer 2**: `cluster-maximum` PermissionSet + `cluster-policy` RBACPolicy in `seam-tenant-{clusterName}`. Created by `reconcileCreate()` L158 in `cluster_rbacpolicy_controller.go`.
- **Layer 3**: Component RBACProfiles only. No per-component PermissionSet. No per-component RBACPolicy.

`RBACPolicy` is never human-authored (CS-INV-008). Cluster-policy ceiling validation against management-maximum happens at `ClusterRBACPolicyReconciler` creation time only (CS-INV-009). Never at RBACProfile admission time (deadlock-prevention invariant).

---

## 4. Primary Data Flows

**EPG recompute**: RBACProfile or PermissionSet change triggers `signalRecompute()` L502 setting annotation `ontai.dev/epg-recompute-requested` --> `EPGReconciler.Reconcile()` L101 reads all profiles + permission sets --> `epg/compute.go` intersection --> writes PermissionSnapshot CRs in `seam-tenant-{cluster}`.

**Tenant PermissionSnapshot delivery**: `TenantSnapshotRunnable` polls management cluster via dynamic `MgmtClient` --> pulls PermissionSnapshot for `ClusterID` from `seam-tenant-{clusterID}` --> SSA-patches local mirror in `Namespace` (ont-system) with label `ontai.dev/snapshot-type=mirrored` --> patches management PermissionSnapshot `status.lastAckedVersion`.

**RBACProfile provisioning (tenant path)**: `reconcileTenantSnapshotPath()` L488 called when `spec.rbacPolicyRef` empty --> lists PermissionSnapshots in `ont-system` labeled `ontai.dev/snapshot-type=mirrored` --> if found: skip ceiling validation, set `Provisioned=true`.

**Cluster onboarding**: New `InfrastructureTalosCluster` --> `ClusterRBACPolicyReconciler.reconcileCreate()` L158 --> `cluster-maximum` PermissionSet + `cluster-policy` RBACPolicy created in `seam-tenant-{cluster}` --> `ensureConductorTenantProfile()` L256 creates `conductor-tenant` RBACProfile in `seam-tenant-{cluster}` (guardian side of Decision C complete; conductor pull loop absent).

---

## 5. Invariants

| ID | Rule | Location |
|----|------|----------|
| CS-INV-001 | Admission webhook is the enforcement mechanism | `internal/webhook/decision.go` |
| CS-INV-002 | CNPG is guardian-only | `internal/database/cnpg.go` |
| CS-INV-003 | Two-phase boot is explicit, never a silent fallback | `internal/database/lazy.go` |
| CS-INV-004 | Bootstrap window closes permanently when webhook becomes operational | `internal/controller/bootstrap_controller.go` |
| CS-INV-005 | `provisioned=true` set exclusively by RBACProfileReconciler | `rbacprofile_controller.go:80` |
| CS-INV-008 | Three-layer RBAC hierarchy; no per-component PermissionSet/RBACPolicy | `controllersets.go`, `cluster_rbacpolicy_controller.go:158` |
| CS-INV-009 | Cluster-policy validation at ClusterRBACPolicyReconciler creation time only | `cluster_rbacpolicy_controller.go:158` |
| CS-INV-010 | `security-system` namespace does not exist; all guardian objects in `seam-system` | Enforced by namespace constants in controllers |

---

## 6. Open Items

**T-25a (no design session required)**: `"RBACProfile"` absent from `InterceptedKinds` at `internal/webhook/decision.go:24`. RBACProfile writes are not gated by admission. Required: add `"RBACProfile"`, two-path routing on `ontai.dev/rbac-profile-type=seam-operator` label.

---

## 7. Test Contract

| Package | Coverage |
|---------|----------|
| `test/unit/controller` | RBACProfileReconciler (tenant snapshot path), ClusterRBACPolicyReconciler, EPGReconciler, AuditSinkReconciler, APIGroupSweepController (IsSystemGroup, CollectThirdPartyGroups, ExplicitGroupsInPermissionSet, Reconcile idempotency + management-maximum patching) |
| `test/unit/webhook` | BootstrapWindow, InterceptedKinds, admission decision logic |
| `test/unit/epg` | EPG computation, ceiling intersection |
| `test/unit/database` | LazyDBClient, SQLAuditWriter, AuditEvent round-trip |
| `test/e2e` | Stub files; all skip when `MGMT_KUBECONFIG` absent; skip reasons reference backlog item IDs |
