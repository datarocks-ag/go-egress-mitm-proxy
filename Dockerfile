FROM golang:1.25-alpine AS builder

WORKDIR /app

# Download dependencies first (better layer caching)
COPY go.mod go.sum ./
RUN go mod download

# Build the binary
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /mitm-proxy .

FROM alpine:3.19

# Install ca-certificates for outbound TLS verification
RUN apk --no-cache add ca-certificates && \
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
