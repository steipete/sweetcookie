package sweetcookie

import (
	"bytes"
	"testing"
)

func TestChromiumDecryptCrypto_InvalidKeyLengths(t *testing.T) {
	// AES-GCM: key length invalid
	encGCM := append([]byte("v10"), bytes.Repeat([]byte{0x00}, 12+16)...)
	if _, err := chromiumDecryptAES256GCM(encGCM, []byte{1, 2, 3}, 0); err == nil {
		t.Fatal("expected error")
	}

	// AES-CBC: key length invalid
	encCBC := append([]byte("v10"), bytes.Repeat([]byte{0x00}, 16)...)
	if _, err := chromiumDecryptAESCBC(encCBC, []byte{1}, 0, false); err == nil {
		t.Fatal("expected error")
	}
}
