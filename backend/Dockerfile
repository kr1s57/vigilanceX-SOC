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

# Build the API binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s -X main.version=1.0.0" \
    -o /build/vigilancex-api \
    ./cmd/api

# Final stage
FROM alpine:3.19

# Install runtime dependencies
RUN apk add --no-cache ca-certificates tzdata wget

# Create non-root user
RUN adduser -D -g '' vigilance

# Set working directory
WORKDIR /app

# Copy binary from builder
COPY --from=builder /build/vigilancex-api /app/vigilancex-api

# Copy scenarios directory (for Detect2Ban)
COPY --from=builder /build/scenarios /app/scenarios

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
