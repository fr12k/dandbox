# Build stage
FROM golang:1.26-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /build

# Cache dependencies
COPY go.mod .
RUN go mod download 2>/dev/null || true

# Build the proxy-sidecar binary
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /usr/local/bin/proxy-sidecar \
    -ldflags="-s -w" \
    ./cmd/proxy-sidecar/

# Runtime stage— minimal image with CA certs for TLS upstream connections
FROM alpine:3.24

RUN apk add --no-cache ca-certificates tzdata curl iptables

COPY --from=builder /usr/local/bin/proxy-sidecar /usr/local/bin/proxy-sidecar

# The proxy listens on :3128 by default
EXPOSE 3128

# Health endpoint
EXPOSE 9099

ENTRYPOINT ["proxy-sidecar"]
