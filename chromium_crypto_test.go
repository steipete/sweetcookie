package sweetcookie

import (
	"bytes"
	"testing"
)

func TestChromiumDecryptAESCBC_StripsHashPrefix(t *testing.T) {
	key := chromiumDeriveAESCBCKey("pw", chromiumAESCBCIterationsLinux)
	plain := append(bytes.Repeat([]byte{0xAA}, 32), []byte("hello")...)
	enc := encryptAESCBCForTest(t, "v10", key, plain)

	got, err := chromiumDecryptAESCBC(enc, key, 30, false)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello" {
		t.Fatalf("want %q got %q", "hello", string(got))
	}
}

func TestChromiumDecryptAESCBC_UnknownPrefixAsPlaintext(t *testing.T) {
	key := chromiumDeriveAESCBCKey("pw", chromiumAESCBCIterationsLinux)
	enc := []byte("plaintext")

	got, err := chromiumDecryptAESCBC(enc, key, 0, true)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "plaintext" {
		t.Fatalf("want %q got %q", "plaintext", string(got))
	}
}

func TestChromiumDecryptAES256GCM_StripsHashPrefix(t *testing.T) {
	key := bytes.Repeat([]byte{0x11}, 32)
	nonce := bytes.Repeat([]byte{0x22}, 12)
	plain := append(bytes.Repeat([]byte{0xBB}, 32), []byte("hello")...)
	enc := encryptAESGCMForTest(t, "v10", key, nonce, plain)

	got, err := chromiumDecryptAES256GCM(enc, key, 24)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello" {
		t.Fatalf("want %q got %q", "hello", string(got))
	}
}

func TestChromiumDecodeCookieValue_StripsLeadingControlChars(t *testing.T) {
	val, ok := chromiumDecodeCookieValue([]byte{0x01, 0x02, 'o', 'k'})
	if !ok {
		t.Fatal("expected ok")
	}
	if val != "ok" {
		t.Fatalf("want %q got %q", "ok", val)
	}
}
