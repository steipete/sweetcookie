//go:build darwin && !ios

package sweetcookie

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestSafariReadCookie_ErrorBranches(t *testing.T) {
	// cookieHeader is 56 bytes; offsets are relative to cookie start.
	// 1) domain offset invalid
	{
		h := make([]byte, 56)
		binary.LittleEndian.PutUint32(h[16:], 0) // DomainOffset
		_, err := safariReadCookie(bytes.NewReader(h), "x", false)
		if err == nil {
			t.Fatal("expected error for invalid domain offset")
		}
	}
	// 2) name offset invalid
	{
		domain := []byte("example.com\x00")
		h := make([]byte, 56+len(domain))
		binary.LittleEndian.PutUint32(h[16:], 56)   // DomainOffset
		binary.LittleEndian.PutUint32(h[20:], 9999) // NameOffset
		copy(h[56:], domain)
		_, err := safariReadCookie(bytes.NewReader(h), "x", false)
		if err == nil {
			t.Fatal("expected error for invalid name offset")
		}
	}
}
