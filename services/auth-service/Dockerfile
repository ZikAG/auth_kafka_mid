# ── Stage 1: Build ────────────────────────────────────────────────────────────
FROM golang:1.22-alpine AS builder

WORKDIR /app

# Install build dependencies.
RUN apk add --no-cache git ca-certificates tzdata

# Download modules first (better layer caching).
COPY go.mod go.sum ./
RUN go mod download

# Copy source and compile a statically linked binary.
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-w -s" -o auth-service .

# ── Stage 2: Distroless runtime ───────────────────────────────────────────────
FROM gcr.io/distroless/static-debian12

# Copy CA certificates for TLS connections to Keycloak.
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy the compiled binary.
COPY --from=builder /app/auth-service /auth-service

EXPOSE 8080

# Run as non-root.
USER nonroot:nonroot

ENTRYPOINT ["/auth-service"]
