// Package cmdutil provides helper utilities for running external commands.
package cmdutil

import (
	"bytes"
	"context"
	"os/exec"
	"strings"
	"time"
)

// runCmd executes a command and returns its combined output.
func RunCmd(ctx context.Context, name string, args ...string) ([]byte, error) {
	// Use background context if the provided context doesn't have a deadline
	if _, ok := ctx.Deadline(); !ok {
		var cancel func()
		ctx, cancel = context.WithTimeout(ctx, 120*time.Second)
		defer cancel()
	}

	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		// Include stderr in the output for debugging
		if stderr.Len() > 0 {
			return stdout.Bytes(), &CmdError{
				Err:    err,
				Stderr: strings.TrimSpace(stderr.String()),
			}
		}
		return stdout.Bytes(), err
	}
	return stdout.Bytes(), nil
}

// CmdError wraps an exec error with stderr output.
type CmdError struct {
	Err    error
	Stderr string
}

func (e *CmdError) Error() string {
	if e.Stderr != "" {
		return e.Err.Error() + ": " + e.Stderr
	}
	return e.Err.Error()
}

func (e *CmdError) Unwrap() error {
	return e.Err
}
