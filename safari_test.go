package sweetcookie

import (
	"context"
	"encoding/binary"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestGet_Safari_BinaryCookies(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Safari binarycookies only on darwin")
	}

	dir := t.TempDir()
	cookieFile := filepath.Join(dir, "Cookies.binarycookies")
	writeSafariBinaryCookies(t, cookieFile)

	res, err := Get(context.Background(), Options{
		URL:      "https://news.ycombinator.com/",
		Browsers: []Browser{BrowserSafari},
		Profiles: map[Browser]string{BrowserSafari: cookieFile},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Cookies) != 1 {
		t.Fatalf("want 1 cookie got %d (warnings=%v)", len(res.Cookies), res.Warnings)
	}
	if res.Cookies[0].Name != "user" || res.Cookies[0].Value != "abc" {
		t.Fatalf("unexpected cookie: %#v", res.Cookies[0])
	}
}

func writeSafariBinaryCookies(t *testing.T, path string) {
	t.Helper()

	domain := "ycombinator.com"
	name := "user"
	cookiePath := "/"
	value := "abc"

	expires := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	creation := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

	record := buildSafariCookieRecord(t, domain, name, cookiePath, value, expires, creation)

	const cookieOffset = 12 // 8-byte page header + 4-byte offset list (1 cookie)
	page := make([]byte, 0, cookieOffset+len(record))
	page = append(page, 0x00, 0x00, 0x01, 0x00)      // page header magic
	page = binary.LittleEndian.AppendUint32(page, 1) // NumCookies
	page = binary.LittleEndian.AppendUint32(page, cookieOffset)
	page = append(page, record...)

	file := make([]byte, 0, 16+len(page)+8)
	file = append(file, []byte("cook")...)
	file = binary.BigEndian.AppendUint32(file, 1)                 // NumPages
	file = binary.BigEndian.AppendUint32(file, uint32(len(page))) // page size
	file = append(file, page...)                                  // page bytes
	file = append(file, 0, 0, 0, 0, 0, 0, 0, 0)                   // checksum

	if err := os.WriteFile(path, file, 0o644); err != nil {
		t.Fatal(err)
	}
}

func buildSafariCookieRecord(t *testing.T, domain, name, path, value string, expires, creation time.Time) []byte {
	t.Helper()

	domainB := append([]byte(domain), 0)
	nameB := append([]byte(name), 0)
	pathB := append([]byte(path), 0)
	valueB := append([]byte(value), 0)

	const headerLen = 56
	domainOff := int32(headerLen)
	nameOff := domainOff + int32(len(domainB))
	pathOff := nameOff + int32(len(nameB))
	valueOff := pathOff + int32(len(pathB))
	size := valueOff + int32(len(valueB))

	buf := make([]byte, 0, size)
	buf = binary.LittleEndian.AppendUint32(buf, uint32(size)) // Size
	buf = binary.LittleEndian.AppendUint32(buf, 0)            // Unknown1
	buf = binary.LittleEndian.AppendUint32(buf, 1)            // Flags (Secure)
	buf = binary.LittleEndian.AppendUint32(buf, 0)            // Unknown2
	buf = binary.LittleEndian.AppendUint32(buf, uint32(domainOff))
	buf = binary.LittleEndian.AppendUint32(buf, uint32(nameOff))
	buf = binary.LittleEndian.AppendUint32(buf, uint32(pathOff))
	buf = binary.LittleEndian.AppendUint32(buf, uint32(valueOff))
	buf = append(buf, 0, 0, 0, 0, 0, 0, 0, 0) // End

	buf = binary.LittleEndian.AppendUint64(buf, float64ToBits(safariSecondsSince2001(expires)))
	buf = binary.LittleEndian.AppendUint64(buf, float64ToBits(safariSecondsSince2001(creation)))

	buf = append(buf, domainB...)
	buf = append(buf, nameB...)
	buf = append(buf, pathB...)
	buf = append(buf, valueB...)

	if int32(len(buf)) != size {
		t.Fatalf("size mismatch: want %d got %d", size, len(buf))
	}
	return buf
}

func safariSecondsSince2001(t time.Time) float64 {
	const macEpoch = int64(978307200)
	sec := t.Unix() - macEpoch
	return float64(sec)
}

func float64ToBits(v float64) uint64 {
	return math.Float64bits(v)
}
