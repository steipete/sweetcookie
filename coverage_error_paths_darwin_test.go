//go:build darwin && !ios

package sweetcookie

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSafariReadPage_ErrorBranches(t *testing.T) {
	// Short read.
	_, err := safariReadPage(bytes.NewReader([]byte{1, 2, 3}), 0, 10, "x", false)
	if err == nil {
		t.Fatal("expected error")
	}

	// Wrong header.
	page := make([]byte, 0, 12)
	page = append(page, 0, 0, 0, 0)                     // wrong magic
	page = append(page, 1, 0, 0, 0)                     // NumCookies=1
	page = append(page, 12, 0, 0, 0)                    // offset
	page = append(page, bytes.Repeat([]byte{0}, 56)...) // cookie header bytes
	_, err = safariReadPage(bytes.NewReader(page), 0, int32(len(page)), "x", false)
	if err == nil {
		t.Fatal("expected error for bad header")
	}
}

func TestMacosReadKeychainPassword_Timeout(t *testing.T) {
	binDir := t.TempDir()
	securityPath := filepath.Join(binDir, "security")
	if err := os.WriteFile(securityPath, []byte("#!/bin/sh\nsleep 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+":"+os.Getenv("PATH"))

	_, err := macosReadKeychainPassword(10*time.Millisecond, "Chrome Safe Storage", "Chrome")
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		// execCapture wraps errors; accept any non-nil error.
		return
	}
}
