# Contributing to guardian

Thank you for your interest in contributing to the Seam platform.

---

## Before you begin

Read the Seam Platform Constitution (`CLAUDE.md` in the ontai root repository)
and the guardian component constitution (`CLAUDE.md` in this repository) before
opening a Pull Request. All contributions must respect the platform invariants
defined in those documents.

Key invariants for this repository:

- Guardian deploys first. All other operators wait for `RBACProfile` to reach
  `provisioned=true`. Do not break this gate.
- CNPG is a guardian-only dependency. No other operator may reference the CNPG
  cluster in `security-system`.
- The admission webhook is the enforcement mechanism. Any change that weakens
  admission webhook coverage requires a Platform Governor review.
- The two-phase boot transition (CRD-only to database-backed) must remain a
  named, explicit transition. Silent fallback is prohibited.

---

## Development setup

```sh
git clone https://github.com/ontai-dev/guardian
cd guardian
go build ./...
go test ./test/unit/...
```

The guardian operator requires a running management cluster with CNPG installed
in `security-system` for integration testing. Unit tests run without a cluster.

---

## Schema changes

All changes to CRD types in `api/v1alpha1/` must be accompanied by a
`docs/guardian-schema.md` update in the same Pull Request. Schema amendments
require Platform Governor approval.

---

## Pull Request checklist

- [ ] `go build ./...` passes with no errors
- [ ] `go test ./test/unit/...` passes
- [ ] No em dashes in any new documentation (use `:` or `-` instead)
- [ ] No shell scripts added (Go only, per INV-001)
- [ ] Distroless image constraint respected (no new runtime dependencies requiring libc)
- [ ] `docs/guardian-schema.md` updated if CRD types changed

---

## Reporting issues

Open an issue at: https://github.com/ontai-dev/guardian/issues

For security vulnerabilities, contact the maintainers directly rather than
opening a public issue.

---

## License

By contributing, you agree that your contributions will be licensed under the
Apache License, Version 2.0. See `LICENSE` for the full text.

---

*guardian - Seam Security Plane*
