//go:build darwin && !ios

package sweetcookie

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestSafariReadPage_CookieOffsetsReadError(t *testing.T) {
	page := make([]byte, 0, 12)
	page = append(page, 0x00, 0x00, 0x01, 0x00)       // magic
	page = binary.LittleEndian.AppendUint32(page, 2)  // NumCookies=2
	page = binary.LittleEndian.AppendUint32(page, 12) // only one offset present

	_, err := safariReadPage(bytes.NewReader(page), 0, int32(len(page)), "x", false)
	if err == nil {
		t.Fatal("expected error")
	}
}
