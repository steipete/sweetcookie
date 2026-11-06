//go:build darwin && !ios

package sweetcookie

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func TestSafariNegativeCountsReturnErrors(t *testing.T) {
	t.Run("pages", func(t *testing.T) {
		path := writeCook(t, func(b *bytes.Buffer) {
			_ = binary.Write(b, binary.BigEndian, int32(-1))
		})
		_, err := safariReadBinaryCookies(context.Background(), path, false)
		if err == nil {
			t.Fatal("expected error for a negative page count")
		}
	})

	t.Run("page size", func(t *testing.T) {
		path := writeCook(t, func(b *bytes.Buffer) {
			_ = binary.Write(b, binary.BigEndian, int32(1))
			_ = binary.Write(b, binary.BigEndian, int32(-1))
		})
		_, err := safariReadBinaryCookies(context.Background(), path, false)
		if err == nil {
			t.Fatal("expected error for a negative page size")
		}
	})

	t.Run("cookies", func(t *testing.T) {
		page := bytes.Buffer{}
		_, _ = page.Write([]byte{0x00, 0x00, 0x01, 0x00})
		_ = binary.Write(&page, binary.LittleEndian, int32(-1))
		path := writeCook(t, func(b *bytes.Buffer) {
			_ = binary.Write(b, binary.BigEndian, int32(1))
			_ = binary.Write(b, binary.BigEndian, int32(page.Len()))
			_, _ = b.Write(page.Bytes())
		})
		_, err := safariReadBinaryCookies(context.Background(), path, false)
		if err == nil {
			t.Fatal("expected error for a negative cookie count")
		}
	})
}

func writeCook(t *testing.T, body func(*bytes.Buffer)) string {
	t.Helper()
	var buf bytes.Buffer
	_, _ = buf.WriteString("cook")
	body(&buf)
	path := filepath.Join(t.TempDir(), "Cookies.binarycookies")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
