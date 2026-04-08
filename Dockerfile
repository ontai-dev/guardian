# Dockerfile — Guardian operator (distroless).
#
# Guardian is a long-running Deployment in seam-system. It owns all RBAC on
# every cluster, runs the admission webhook, and manages PermissionSnapshots.
# Distroless: no shell, no package manager. Zero attack surface. INV-022.
# guardian-schema.md §6.

FROM golang:1.25 AS builder
WORKDIR /build
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /bin/guardian \
    ./cmd/ont-security

FROM gcr.io/distroless/base:nonroot
COPY --from=builder /bin/guardian /usr/local/bin/guardian

USER 65532:65532
ENTRYPOINT ["/usr/local/bin/guardian"]
