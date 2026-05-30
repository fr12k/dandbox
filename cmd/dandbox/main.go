package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/fr12k/dandbox/internal/daemon"
)

func run(args []string) error {
	log.SetFlags(log.Ldate | log.Ltime | log.Lmsgprefix)
	log.SetPrefix("[sbxsandbox] ")

	fs := flag.NewFlagSet("sbxsandbox", flag.ContinueOnError)
	socketPath := fs.String("socket", "", "Unix socket path for the API (default: ~/.config/sbxsandbox/sbxsandbox.sock)")
	dockerSocket := fs.String("docker-socket", "", "Docker Engine Unix socket path")
	stateDir := fs.String("state-dir", "", "Directory for sandbox state persistence")
	policyDir := fs.String("policy-dir", "", "Directory for policy persistence")
	caDir := fs.String("ca-dir", "", "Directory for CA certificates")
	proxySidecarImage := fs.String("proxy-sidecar-image", "", "Docker image for the proxy sidecar container")

	if err := fs.Parse(args); err != nil {
		return err
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("cannot determine home directory: %w", err)
	}
	if *socketPath == "" {
		*socketPath = filepath.Join(home, ".config", "sbxsandbox", "sbxsandbox.sock")
	}
	if *stateDir == "" {
		*stateDir = filepath.Join(home, ".local", "state", "sbxsandbox")
	}

	log.Printf("Starting sbxsandbox...")
	log.Printf("  API socket: %s", *socketPath)
	log.Printf("  Sidecar image: %s", *proxySidecarImage)
	log.Printf("  State dir:  %s", *stateDir)

	cfg := daemon.DaemonConfig{
		SocketPath:        *socketPath,
		PolicyDir:         *policyDir,
		CACertDir:         *caDir,
		DockerSocket:      *dockerSocket,
		StateDir:          *stateDir,
		ProxySidecarImage: "containifyci/proxy-sidecar:latest",
		ProxySidecarBin:   os.Getenv("PROXY_SIDECAR_BIN"),
	}

	d, err := daemon.NewDaemon(cfg)
	if err != nil {
		return fmt.Errorf("failed to initialize daemon: %w", err)
	}

	if err := d.Start(); err != nil {
		return fmt.Errorf("failed to start daemon: %w", err)
	}

	// Wait for signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	sig := <-quit
	log.Printf("Received signal %v, shutting down...", sig)

	_ = d.Stop()
	log.Printf("Shutdown complete")
	return nil
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}