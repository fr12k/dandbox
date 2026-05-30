package cmdutil

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestRunCmd_Success(t *testing.T) {
	ctx := context.Background()
	out, err := RunCmd(ctx, "echo", "hello", "world")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := string(out)
	expected := "hello world\n"
	if got != expected {
		t.Errorf("expected %q, got %q", expected, got)
	}
}

func TestRunCmd_CommandFails_WithStderr(t *testing.T) {
	ctx := context.Background()
	// Command that writes to stderr and exits with non-zero
	_, err := RunCmd(ctx, "sh", "-c", "echo 'error message' >&2; exit 1")
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	var cmdErr *CmdError
	if !errors.As(err, &cmdErr) {
		t.Fatalf("expected *CmdError, got %T: %v", err, err)
	}

	if cmdErr.Stderr == "" {
		t.Error("expected non-empty stderr in CmdError")
	}
	if cmdErr.Stderr != "error message" {
		t.Errorf("expected stderr 'error message', got %q", cmdErr.Stderr)
	}
}

func TestRunCmd_CommandFails_WithoutStderr(t *testing.T) {
	ctx := context.Background()
	// "false" command exits with status 1 and no stderr output
	_, err := RunCmd(ctx, "false")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	// Should be a raw exit error, not wrapped in CmdError
	// (since there's no stderr output)
	var cmdErr *CmdError
	if errors.As(err, &cmdErr) {
		// It's ok if it wraps in CmdError with empty stderr
		if cmdErr.Stderr != "" {
			t.Errorf("expected empty stderr, got %q", cmdErr.Stderr)
		}
	}
	// Either way, the error should indicate failure
}

func TestRunCmd_CommandNotFound(t *testing.T) {
	ctx := context.Background()
	_, err := RunCmd(ctx, "nonexistent_command_that_does_not_exist_12345")
	if err == nil {
		t.Fatal("expected error for nonexistent command, got nil")
	}
}

func TestRunCmd_WithContextCancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	// Use a command that would take longer than the context allows
	_, err := RunCmd(ctx, "sleep", "10")
	if err == nil {
		t.Fatal("expected error due to context cancellation, got nil")
	}
}

func TestCmdError_Error(t *testing.T) {
	tests := []struct {
		name    string
		cmdErr  *CmdError
		wantMsg string
	}{
		{
			name:    "with stderr",
			cmdErr:  &CmdError{Err: fmt.Errorf("exit status 1"), Stderr: "something failed"},
			wantMsg: "exit status 1: something failed",
		},
		{
			name:    "without stderr",
			cmdErr:  &CmdError{Err: fmt.Errorf("exit status 1"), Stderr: ""},
			wantMsg: "exit status 1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.cmdErr.Error()
			if got != tt.wantMsg {
				t.Errorf("CmdError.Error() = %q, want %q", got, tt.wantMsg)
			}
		})
	}
}

func TestCmdError_Unwrap(t *testing.T) {
	innerErr := fmt.Errorf("inner error")
	cmdErr := &CmdError{Err: innerErr, Stderr: "stderr output"}

	unwrapped := cmdErr.Unwrap()
	if unwrapped != innerErr {
		t.Errorf("expected unwrapped to be inner error, got %v", unwrapped)
	}
}

func TestCmdError_Is(t *testing.T) {
	innerErr := fmt.Errorf("base error")
	cmdErr := &CmdError{Err: innerErr, Stderr: "some stderr"}

	// Verify Unwrap works correctly
	unwrapped := errors.Unwrap(cmdErr)
	if unwrapped != innerErr {
		t.Errorf("expected unwrapped error to be innerErr, got %v", unwrapped)
	}
}

func TestRunCmd_EmptyArgs(t *testing.T) {
	ctx := context.Background()
	out, err := RunCmd(ctx, "echo")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// echo with no args just prints a newline
	if string(out) != "\n" {
		t.Errorf("expected just newline, got %q", string(out))
	}
}