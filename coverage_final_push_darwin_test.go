//go:build darwin && !ios

package sweetcookie

import (
	"bytes"
	"testing"
)

func TestSafariReadString_MissingNullTerminator(t *testing.T) {
	// No null terminator -> ReadString should error.
	_, err := safariReadString(bytes.NewReader([]byte("abc")), "x", 0, 1)
	if err == nil {
		t.Fatal("expected error")
	}
}
