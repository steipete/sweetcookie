//go:build darwin && !ios

package sweetcookie

import (
	"bytes"
	"testing"
)

func TestSafariReadString_InvalidOffset(t *testing.T) {
	_, err := safariReadString(bytes.NewReader([]byte("abc")), "x", 0, 0)
	if err == nil {
		t.Fatal("expected error")
	}
}
