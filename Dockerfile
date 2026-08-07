FROM golang:1.25-alpine AS builder

WORKDIR /app

# Download dependencies first (better layer caching)
COPY go.mod go.sum ./
RUN go mod download

# Build the binary
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w -X main.version=${VERSION}" -o /mitm-proxy ./cmd/mitm-proxy

FROM alpine:3.24

# Build metadata, as OCI image annotations.
#
# Declared here rather than left to the CI metadata action alone so that an image
# built with `make docker-build`, or by anyone with a clone, describes itself the
# same way the published one does. The action derives its description from the
# GitHub repository description, which is empty -- that is why the published
# package read "No description provided" -- so the value lives here where it is
# reviewable instead of in a repository setting.
#
# VERSION, REVISION and CREATED are per-build and default to placeholders; the
# release workflow and the Makefile pass real values. A published image with
# revision=unknown means it was built outside those paths.
ARG VERSION=dev
ARG REVISION=unknown
ARG CREATED=1970-01-01T00:00:00Z

LABEL org.opencontainers.image.title="go-egress-proxy" \
      org.opencontainers.image.description="MITM HTTP/HTTPS egress proxy with split-brain DNS: ACL policy (whitelist/blacklist/passthrough), domain rewrites to internal targets, header injection and selective request tracing." \
      org.opencontainers.image.source="https://github.com/datarocks-ag/go-egress-mitm-proxy" \
      org.opencontainers.image.url="https://github.com/datarocks-ag/go-egress-mitm-proxy" \
      org.opencontainers.image.documentation="https://github.com/datarocks-ag/go-egress-mitm-proxy/blob/main/README.md" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.vendor="Data Rocks AG" \
      org.opencontainers.image.base.name="docker.io/library/alpine:3.24" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.created="${CREATED}"

# Upgrade all packages to pick up security fixes, then install ca-certificates
RUN apk --no-cache upgrade && \
    apk --no-cache add ca-certificates && \
    adduser -D -u 1000 proxy

WORKDIR /app

COPY --from=builder /mitm-proxy .

# Default config location (mount your own config)
ENV CONFIG_PATH=/app/config.yaml

# Switch to non-root user
USER proxy

EXPOSE 8080 9090

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget -qO- http://localhost:9090/healthz || exit 1

ENTRYPOINT ["./mitm-proxy"]
