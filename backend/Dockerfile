# Build stage
FROM golang:1.22-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Set working directory
WORKDIR /build

# Copy go mod files first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Ensure dependencies are synced (for new additions)
RUN go mod tidy

# Build the API binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s -X main.version=1.0.0" \
    -o /build/vigilancex-api \
    ./cmd/api

# Build the password reset tool (v2.6)
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s" \
    -o /build/reset-password \
    ./cmd/reset-password

# Final stage
FROM alpine:3.19

# Install runtime dependencies
RUN apk add --no-cache ca-certificates tzdata wget

# Create non-root user
RUN adduser -D -g '' vigilance

# Set working directory
WORKDIR /app

# Copy binaries from builder
COPY --from=builder /build/vigilancex-api /app/vigilancex-api
COPY --from=builder /build/reset-password /app/reset-password

# Copy scenarios directory (for Detect2Ban)
COPY --from=builder /build/scenarios /app/scenarios

# Create data directory for license persistence (v2.9)
RUN mkdir -p /app/data

# Set ownership
RUN chown -R vigilance:vigilance /app

# Switch to non-root user
USER vigilance

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget -q --spider http://localhost:8080/health || exit 1

# Run the application
ENTRYPOINT ["/app/vigilancex-api"]
