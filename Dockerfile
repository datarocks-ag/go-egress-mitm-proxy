FROM golang:1.25-alpine AS builder

WORKDIR /app

# Download dependencies first (better layer caching)
COPY go.mod go.sum ./
RUN go mod download

# Build the binary
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w -X main.version=${VERSION}" -o /mitm-proxy ./cmd/mitm-proxy

FROM alpine:3.19

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
