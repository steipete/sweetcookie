//go:build darwin && !ios

package sweetcookie

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSafariReadBinaryCookies_PageSizesReadError(t *testing.T) {
	p := filepath.Join(t.TempDir(), "Cookies.binarycookies")
	// "cook" + NumPages=1, but no page size bytes.
	b := make([]byte, 0, 8)
	b = append(b, []byte("cook")...)
	b = binary.BigEndian.AppendUint32(b, 1)
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := safariReadBinaryCookies(context.Background(), p, false)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestSafariReadCookie_NoExpiry(t *testing.T) {
	// Reuse the binarycookies writer but set expiration to the mac epoch (secsSince2001 == 0).
	dir := t.TempDir()
	cookieFile := filepath.Join(dir, "Cookies.binarycookies")

	expires := time.Unix(978307200, 0).UTC()
	creation := time.Unix(978307200, 0).UTC()
	record := buildSafariCookieRecord(t, "example.com", "a", "/", "b", expires, creation)

	page := make([]byte, 0, 12+len(record))
	page = append(page, 0x00, 0x00, 0x01, 0x00)
	page = binary.LittleEndian.AppendUint32(page, 1)
	page = binary.LittleEndian.AppendUint32(page, 12)
	page = append(page, record...)

	file := make([]byte, 0, 16+len(page)+8)
	file = append(file, []byte("cook")...)
	file = binary.BigEndian.AppendUint32(file, 1)
	file = binary.BigEndian.AppendUint32(file, uint32(len(page)))
	file = append(file, page...)
	file = append(file, make([]byte, 8)...)

	if err := os.WriteFile(cookieFile, file, 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := Get(context.Background(), Options{
		URL:      "https://example.com/",
		Browsers: []Browser{BrowserSafari},
		Profiles: map[Browser]string{BrowserSafari: cookieFile},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Cookies) != 1 {
		t.Fatalf("want 1 cookie got %d", len(res.Cookies))
	}
	if res.Cookies[0].Expires != nil {
		t.Fatal("expected no Expires")
	}
}

func TestSafariReadString_ReadError(t *testing.T) {
	// Seek into a short buffer; read should error.
	_, err := safariReadString(bytes.NewReader([]byte{0, 1, 2}), "x", 0, 100)
	if err == nil {
		t.Fatal("expected error")
	}
}
