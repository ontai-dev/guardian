# guardian

**Seam Security Plane operator**
**API Group:** `security.ontai.dev`
**Image:** `registry.ontai.dev/ontai-dev/guardian:<semver>`

---

## What this repository is

`guardian` is the intelligent operator in the Seam platform. It is the only ONT
operator with genuine in-process logic beyond the thin reconciler pattern.

Guardian owns all RBAC on every cluster. No component provisions its own RBAC.
Guardian's admission webhook gates every RBAC resource written to any cluster in
the Seam stack.

---

## CRDs

| Kind | API Group | Role |
|---|---|---|
| `RBACProfile` | `security.ontai.dev` | Declares RBAC policy intent for a tenant or operator |
| `RBACPolicy` | `security.ontai.dev` | Concrete policy rule set applied to a principal set |
| `PermissionSet` | `security.ontai.dev` | Compiled effective permissions for a principal |
| `PermissionSnapshot` | `security.ontai.dev` | Signed point-in-time permission record for target delivery |
| `PermissionSnapshotReceipt` | `security.ontai.dev` | Acknowledgement of snapshot delivery on a target cluster |
| `IdentityProvider` | `security.ontai.dev` | OIDC or LDAP identity source configuration |
| `IdentityBinding` | `security.ontai.dev` | Binding between a domain identity and a Kubernetes principal |
| `InfrastructureLineageIndex` | `security.ontai.dev` | Sealed causal chain index (one per root declaration) |
| `SeamMembership` | `security.ontai.dev` | Domain membership record for a principal on a target cluster |

---

## Architecture

Guardian has two operating modes.

**Management cluster (role=management):**
- Computes the Effective Permission Graph (EPG) in-process from RBACProfile and RBACPolicy objects.
- Generates signed PermissionSnapshot CRs for delivery to target clusters.
- Runs a CNPG-backed persistent store for EPG state, audit events, and identity resolution logs.
- Deploys first. Its `RBACProfile` reaching `provisioned=true` is the gate that unblocks all other operators.

**Target cluster (Conductor agent on target, Guardian runner on admission):**
- Runs the local admission webhook that intercepts all RBAC resources.
- Enforces the `ontai.dev/rbac-owner=guardian` annotation on every RBAC object.
- Serves the local PermissionService gRPC endpoint for authorization decisions.

---

## Two-phase boot

Guardian boots in two phases:

1. **CRD-only phase** (before CNPG is reachable): reconcilers start with an in-memory
   EPG stub. The bootstrap RBAC window is open. Guardian emits a named `BootstrapWindow`
   condition during this phase.

2. **Database-backed phase** (after CNPG connection is confirmed): full EPG computation
   starts. The `BootstrapWindow` condition closes permanently when the admission webhook
   becomes operational. This transition is named and never a silent fallback.

See `guardian-design.md` for the full boot sequence and `docs/guardian-schema.md` for
the API contract.

---

## Building

```sh
go build ./cmd/guardian
```

The binary is built into a distroless container image:

```sh
docker build -t registry.ontai.dev/ontai-dev/guardian:<semver> .
```

---

## Testing

```sh
go test ./test/unit/...
```

---

## Schema and design reference

- `docs/guardian-schema.md` - API contract, field definitions, status conditions
- `guardian-design.md` - Implementation architecture and reconciler design

---

*guardian - Seam Security Plane*
*Apache License, Version 2.0*
