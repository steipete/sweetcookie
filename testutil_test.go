package sweetcookie

import (
	"crypto/aes"
	"crypto/cipher"
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

func openTestSQLite(t *testing.T, path string) *sql.DB {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(path)+"?mode=rwc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func pkcs7Pad(t *testing.T, b []byte) []byte {
	t.Helper()
	paddingLen := aes.BlockSize - (len(b) % aes.BlockSize)
	if paddingLen == 0 {
		paddingLen = aes.BlockSize
	}
	out := make([]byte, 0, len(b)+paddingLen)
	out = append(out, b...)
	for i := 0; i < paddingLen; i++ {
		out = append(out, byte(paddingLen))
	}
	return out
}

func encryptAESCBCForTest(t *testing.T, prefix string, key []byte, plaintext []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	iv := []byte(chromiumAESCBCIV)
	padded := pkcs7Pad(t, plaintext)
	ciphertext := make([]byte, len(padded))
	cbc := cipher.NewCBCEncrypter(block, iv)
	cbc.CryptBlocks(ciphertext, padded)
	return append([]byte(prefix), ciphertext...)
}

func encryptAESGCMForTest(t *testing.T, prefix string, key []byte, nonce []byte, plaintext []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	ciphertextAndTag := aesgcm.Seal(nil, nonce, plaintext, nil)
	out := make([]byte, 0, len(prefix)+len(nonce)+len(ciphertextAndTag))
	out = append(out, []byte(prefix)...)
	out = append(out, nonce...)
	out = append(out, ciphertextAndTag...)
	return out
}
