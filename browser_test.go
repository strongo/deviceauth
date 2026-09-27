package deviceauth

import (
	"errors"
	"strings"
	"testing"
)

func TestOpenBrowser(t *testing.T) {
	// Restore seams after test
	origExec := execCommandStart
	origGOOS := runtimeGOOS
	defer func() {
		execCommandStart = origExec
		runtimeGOOS = origGOOS
	}()

	_ = origExec("true")

	// Invalid URL (relative)
	if err := OpenBrowser("/path"); err == nil {
		t.Error("expected error for relative URL")
	}

	// Unsupported platform
	runtimeGOOS = "plan9"
	if err := OpenBrowser("https://example.com"); err == nil {
		t.Error("expected error for unsupported platform")
	}

	// Exec command start returns error
	runtimeGOOS = "darwin"
	execCommandStart = func(name string, args ...string) error {
		return errors.New("exec failed")
	}
	if err := OpenBrowser("https://example.com"); err == nil || !strings.Contains(err.Error(), "exec failed") {
		t.Errorf("expected exec failed error, got %v", err)
	}

	// Exec command start succeeds
	execCommandStart = func(name string, args ...string) error {
		if name != "open" || len(args) != 1 || args[0] != "https://example.com" {
			t.Errorf("unexpected command: %s %v", name, args)
		}
		return nil
	}
	if err := OpenBrowser("https://example.com"); err != nil {
		t.Errorf("expected success, got %v", err)
	}
}

func TestBrowserCommand_Unsupported(t *testing.T) {
	_, _, err := browserCommand("unsupported_os", "https://example.com")
	if err == nil {
		t.Error("expected error for unsupported OS")
	}
}
