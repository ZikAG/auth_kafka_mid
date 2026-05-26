FROM golang:1.22-alpine AS builder
WORKDIR /app

# Install build dependencies including git (needed by go mod download for VCS
# info) and CA certificates so HTTPS requests succeed during the build.
RUN apk add --no-cache git ca-certificates

# Download dependencies first so this layer is cached when only source changes.
COPY go.mod go.sum ./
RUN go mod download

# Copy application source and build a fully static binary.
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-w -s" -o test-client .

# ---------------------------------------------------------------------------
# Final image – distroless for minimal attack surface.
# The "static-debian12" variant has no shell, no package manager, nothing
# except libc stubs and the certificate store.
# ---------------------------------------------------------------------------
FROM gcr.io/distroless/static-debian12

# Copy CA bundle from the builder so the binary can validate TLS connections
# to Keycloak / auth-service without mounting external certs.
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy the compiled binary.
COPY --from=builder /app/test-client /test-client

# Run as the built-in non-root user provided by distroless.
USER nonroot:nonroot

ENTRYPOINT ["/test-client"]
