//go:build darwin && !ios

package sweetcookie

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func readSafariCookies(ctx context.Context, override string, _ []requestOrigin, _ Options) ([]Cookie, []string, error) {
	files, warnings := safariCookieFiles(override)
	if len(files) == 0 {
		return nil, append(warnings, "sweetcookie: Safari cookie store not found"), nil
	}

	var out []Cookie
	for i, p := range files {
		cookies, err := safariReadBinaryCookies(ctx, p, i > 0)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("sweetcookie: Safari read failed: %v", err))
			continue
		}
		out = append(out, cookies...)
	}
	return out, warnings, nil
}

func safariCookieFiles(override string) ([]string, []string) {
	override = strings.TrimSpace(override)
	if override != "" {
		if fileExists(override) {
			return []string{override}, nil
		}
		return nil, []string{fmt.Sprintf("sweetcookie: Safari Cookies.binarycookies not found at %q", override)}
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return nil, nil
	}
	paths := []string{
		filepath.Join(home, "Library", "Containers", "com.apple.Safari", "Data", "Library", "Cookies", "Cookies.binarycookies"),
		filepath.Join(home, "Library", "Cookies", "Cookies.binarycookies"),
	}

	var out []string
	for _, p := range paths {
		if fileExists(p) {
			out = append(out, p)
		}
	}
	return out, nil
}

type safariFileHeader struct {
	Magic    [4]byte
	NumPages int32
}

type safariPageHeader struct {
	Header     [4]byte
	NumCookies int32
}

type safariCookieHeader struct {
	Size           int32
	Unknown1       int32
	Flags          int32
	Unknown2       int32
	DomainOffset   int32
	NameOffset     int32
	PathOffset     int32
	ValueOffset    int32
	End            [8]byte
	ExpirationDate float64
	CreationDate   float64
}

func safariReadBinaryCookies(ctx context.Context, filename string, isFallback bool) ([]Cookie, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	var header safariFileHeader
	if err := binary.Read(f, binary.BigEndian, &header); err != nil {
		return nil, err
	}
	if string(header.Magic[:]) != "cook" {
		return nil, fmt.Errorf("unexpected magic %q", string(header.Magic[:]))
	}

	pageSizes := make([]int32, header.NumPages)
	if err := binary.Read(f, binary.BigEndian, &pageSizes); err != nil {
		return nil, err
	}

	var out []Cookie
	for i, size := range pageSizes {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		cookies, err := safariReadPage(f, i, size, filename, isFallback)
		if err != nil {
			return nil, err
		}
		out = append(out, cookies...)
	}

	// checksum (ignored)
	var checksum [8]byte
	_ = binary.Read(f, binary.BigEndian, &checksum)

	return out, nil
}

func safariReadPage(r io.Reader, page int, pageSize int32, storePath string, isFallback bool) ([]Cookie, error) {
	b := make([]byte, pageSize)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, fmt.Errorf("page %d: %w", page, err)
	}
	br := bytes.NewReader(b)

	var header safariPageHeader
	if err := binary.Read(br, binary.LittleEndian, &header); err != nil {
		return nil, fmt.Errorf("page %d: %w", page, err)
	}

	want := [4]byte{0x00, 0x00, 0x01, 0x00}
	if header.Header != want {
		return nil, fmt.Errorf("page %d: unexpected header %v", page, header.Header)
	}

	offsets := make([]int32, header.NumCookies)
	if err := binary.Read(br, binary.LittleEndian, &offsets); err != nil {
		return nil, fmt.Errorf("page %d: %w", page, err)
	}

	out := make([]Cookie, 0, len(offsets))
	for i, off := range offsets {
		if _, err := br.Seek(int64(off), io.SeekStart); err != nil {
			return nil, fmt.Errorf("page %d cookie %d: %w", page, i, err)
		}
		c, err := safariReadCookie(br, storePath, isFallback)
		if err != nil {
			return nil, fmt.Errorf("page %d cookie %d: %w", page, i, err)
		}
		out = append(out, c)
	}
	return out, nil
}

func safariReadCookie(r io.ReadSeeker, storePath string, isFallback bool) (Cookie, error) {
	start, _ := r.Seek(0, io.SeekCurrent)

	var h safariCookieHeader
	if err := binary.Read(r, binary.LittleEndian, &h); err != nil {
		return Cookie{}, err
	}

	domain, err := safariReadString(r, "domain", start, h.DomainOffset)
	if err != nil {
		return Cookie{}, err
	}
	name, err := safariReadString(r, "name", start, h.NameOffset)
	if err != nil {
		return Cookie{}, err
	}
	path, err := safariReadString(r, "path", start, h.PathOffset)
	if err != nil {
		return Cookie{}, err
	}
	value, err := safariReadString(r, "value", start, h.ValueOffset)
	if err != nil {
		return Cookie{}, err
	}

	var expires *time.Time
	if h.ExpirationDate != 0 {
		t := safariTime(h.ExpirationDate)
		expires = &t
	}

	c := Cookie{
		Name:     name,
		Value:    value,
		Domain:   normalizeHost(domain),
		Path:     path,
		Secure:   (h.Flags & 1) != 0,
		HTTPOnly: (h.Flags & 4) != 0,
		Expires:  expires,
		Source: Source{
			Browser:    BrowserSafari,
			Profile:    "Default",
			StorePath:  storePath,
			IsFallback: isFallback,
		},
	}
	if c.Path == "" {
		c.Path = "/"
	}
	return c, nil
}

func safariReadString(r io.ReadSeeker, field string, start int64, offset int32) (string, error) {
	if offset <= 0 {
		return "", errors.New("invalid offset")
	}
	if _, err := r.Seek(start+int64(offset), io.SeekStart); err != nil {
		return "", fmt.Errorf("seek %q: %w", field, err)
	}
	br := bufio.NewReader(r)
	s, err := br.ReadString(0)
	if err != nil {
		return "", fmt.Errorf("read %q: %w", field, err)
	}
	return strings.TrimSuffix(s, "\x00"), nil
}

func safariTime(secsSince2001 float64) time.Time {
	// Safari uses seconds since 2001-01-01 00:00:00 UTC.
	const macEpoch = int64(978307200)
	sec := int64(secsSince2001)
	nsec := int64((secsSince2001 - float64(sec)) * 1e9)
	return time.Unix(macEpoch+sec, nsec).UTC()
}
