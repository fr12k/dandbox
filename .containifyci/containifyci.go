//go:generate sh -c "if [ ! -f go.mod ]; then echo 'Initializing go.mod...'; go mod init .containifyci; else echo 'go.mod already exists. Skipping initialization.'; fi"
//go:generate go get github.com/containifyci/engine-ci/protos2
//go:generate go get github.com/containifyci/engine-ci/client
//go:generate go mod tidy

package main

import (
	"os"

	"github.com/containifyci/engine-ci/client/pkg/build"
	"github.com/containifyci/engine-ci/protos2"
)

func registryAuth() map[string]*protos2.ContainerRegistry {
	return map[string]*protos2.ContainerRegistry{
		"docker.io": {
			Username: "env:DOCKER_USER",
			Password: "env:DOCKER_TOKEN",
		},
		"ghcr.io": {
			Username: "USERNAME",
			Password: "env:GHCR_TOKEN",
		},
	}
}

func main() {
	os.Chdir("../")
	// Static fallback configuration
	daemon := build.NewGoServiceBuild("dandbox")
	daemon.Verbose = false
	daemon.File = "cmd/dandbox/main.go"
	daemon.Properties = map[string]*build.ListValue{
		"goreleaser": build.NewList("true"),
	}
	daemon.Image = ""

	proxy := build.NewGoServiceBuild("proxy-sidecar")
	proxy.Verbose = false
	proxy.File = "cmd/proxy-sidecar/main.go"
	proxy.Image = "proxy-sidecar"
	proxy.Registry = "containifyci"
	proxy.Registries = registryAuth()
	// proxy.ContainerFiles = map[string]*protos2.ContainerFile{
	// 	"build": DockerFile(),
	// }
	build.Build(daemon, proxy)
}

func DockerFile() *protos2.ContainerFile {
	return &protos2.ContainerFile{
		Name: "golang:1.26-alpine-custom",
		Content: `# Build stage
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
FROM alpine:3.23

RUN apk add --no-cache ca-certificates tzdata curl

COPY --from=builder /usr/local/bin/proxy-sidecar /usr/local/bin/proxy-sidecar

# The proxy listens on :3128 by default
EXPOSE 3128

# Health endpoint
EXPOSE 9099

ENTRYPOINT ["proxy-sidecar"]
`,
	}
}
