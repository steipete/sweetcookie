package sweetcookie

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestReadFromBrowser_InlineAndUnknown(t *testing.T) {
	// Inline is handled separately; browser dispatch should be a no-op.
	if cookies, warnings, err := readFromBrowser(context.Background(), BrowserInline, nil, Options{}); err != nil || len(warnings) != 0 || len(cookies) != 0 {
		t.Fatalf("unexpected: %v %v %v", cookies, warnings, err)
	}
	_, warnings, _ := readFromBrowser(context.Background(), Browser("nope"), nil, Options{})
	if len(warnings) == 0 {
		t.Fatal("expected warning")
	}
}

func TestFirefoxRowToCookie_SetsDefaultPath(t *testing.T) {
	c, ok := firefoxRowToCookie(firefoxDB{path: "x", profile: "p"}, firefoxRow{
		host:  ".example.com",
		name:  "a",
		value: "b",
		path:  "",
	})
	if !ok {
		t.Fatal("expected ok")
	}
	if c.Path != "/" {
		t.Fatalf("want / got %q", c.Path)
	}
	if c.Expires != nil {
		t.Fatal("expected nil expires")
	}
}

func TestChromiumHostWhereClause_EmptyHosts(t *testing.T) {
	where, args := chromiumHostWhereClause(nil)
	if where != "1=1" || len(args) != 0 {
		t.Fatalf("unexpected: %q %v", where, args)
	}
}

func TestFirefoxHostWhereClause_EmptyHosts(t *testing.T) {
	where, args := firefoxHostWhereClause(nil)
	if where != "1=1" || len(args) != 0 {
		t.Fatalf("unexpected: %q %v", where, args)
	}
}

func TestChromiumResolveStoreFromOverride_MissingProfileName(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Setenv("HOME", t.TempDir())
	}
	stores, warnings := chromiumResolveStoreFromOverride(BrowserChrome, "NoSuchProfile")
	if len(stores) != 0 || len(warnings) == 0 {
		t.Fatalf("expected warnings: %v %v", stores, warnings)
	}
}

func TestChromiumResolveStoreFromOverride_ProfileDir(t *testing.T) {
	dir := t.TempDir()
	profileDir := filepath.Join(dir, "Default")
	if err := os.MkdirAll(filepath.Join(profileDir, "Network"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(profileDir, "Network", "Cookies"), []byte{}, 0o644); err != nil {
		t.Fatal(err)
	}
	stores, warnings := chromiumResolveStoreFromOverride(BrowserChrome, profileDir)
	if len(warnings) != 0 || len(stores) == 0 {
		t.Fatalf("unexpected: %v %v", stores, warnings)
	}
}

func TestSafariReadBinaryCookies_PageSizesReadError(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin-only")
	}
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
	if runtime.GOOS != "darwin" {
		t.Skip("darwin-only")
	}

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
	if runtime.GOOS != "darwin" {
		t.Skip("darwin-only")
	}
	// Seek into a short buffer; read should error.
	_, err := safariReadString(bytes.NewReader([]byte{0, 1, 2}), "x", 0, 100)
	if err == nil {
		t.Fatal("expected error")
	}
}
