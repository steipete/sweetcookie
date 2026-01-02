package sweetcookie

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1" //nolint:gosec // Chromium PBKDF2 uses SHA1 ("saltysalt", sha1) for legacy cookie encryption.
	"errors"
	"fmt"
	"unicode/utf8"

	"golang.org/x/crypto/pbkdf2"
)

const (
	chromiumAESCBCSalt            = "saltysalt"
	chromiumAESCBCIV              = "                " // 16 spaces
	chromiumAESCBCIterationsLinux = 1
	chromiumAESCBCIterationsMacOS = 1003
	chromiumAESCBCKeyLen          = 16
)

func chromiumDeriveAESCBCKey(password string, iterations int) []byte {
	return pbkdf2.Key([]byte(password), []byte(chromiumAESCBCSalt), iterations, chromiumAESCBCKeyLen, sha1.New)
}

func chromiumDecryptAESCBC(encrypted []byte, key []byte, metaVersion int64, treatUnknownPrefixAsPlaintext bool) ([]byte, error) {
	if len(encrypted) == 0 {
		return nil, errors.New("empty encrypted value")
	}
	if len(encrypted) <= 3 {
		return nil, fmt.Errorf("encrypted value too short (%d<=3)", len(encrypted))
	}

	if !hasChromiumVersionPrefix(encrypted) {
		if !treatUnknownPrefixAsPlaintext {
			return nil, errors.New("missing v## prefix")
		}
		plain := make([]byte, len(encrypted))
		copy(plain, encrypted)
		return plain, nil
	}

	ciphertext := encrypted[3:]
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, errors.New("cipher input not full blocks")
	}

	out := make([]byte, len(ciphertext))
	cbc := cipher.NewCBCDecrypter(block, []byte(chromiumAESCBCIV))
	cbc.CryptBlocks(out, ciphertext)

	out, err = removePKCS7Padding(out)
	if err != nil {
		return nil, err
	}
	out = chromiumStripHashPrefix(out, metaVersion)
	return out, nil
}

func chromiumDecryptAES256GCM(encrypted []byte, key []byte, metaVersion int64) ([]byte, error) {
	if len(encrypted) < 3+12+16 {
		return nil, errors.New("encrypted value too short")
	}
	if !hasChromiumVersionPrefix(encrypted) {
		return nil, errors.New("missing v## prefix")
	}

	payload := encrypted[3:]
	nonce := payload[:12]
	ciphertextAndTag := payload[12:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plain, err := aesgcm.Open(nil, nonce, ciphertextAndTag, nil)
	if err != nil {
		return nil, err
	}
	plain = chromiumStripHashPrefix(plain, metaVersion)
	return plain, nil
}

func chromiumStripHashPrefix(plain []byte, metaVersion int64) []byte {
	if metaVersion >= 24 && len(plain) >= 32 {
		return plain[32:]
	}
	return plain
}

func hasChromiumVersionPrefix(b []byte) bool {
	if len(b) < 3 {
		return false
	}
	if b[0] != 'v' {
		return false
	}
	return isDigit(b[1]) && isDigit(b[2])
}

func isDigit(b byte) bool { return b >= '0' && b <= '9' }

func removePKCS7Padding(b []byte) ([]byte, error) {
	if len(b) == 0 {
		return b, nil
	}
	paddingLen := int(b[len(b)-1])
	if paddingLen <= 0 || paddingLen > aes.BlockSize || paddingLen > len(b) {
		return nil, fmt.Errorf("invalid padding length: %d", paddingLen)
	}
	for _, p := range b[len(b)-paddingLen:] {
		if int(p) != paddingLen {
			return nil, errors.New("invalid padding bytes")
		}
	}
	return b[:len(b)-paddingLen], nil
}

func chromiumDecodeCookieValue(b []byte) (string, bool) {
	b = stripLeadingControlBytes(b)
	if !utf8.Valid(b) {
		return "", false
	}
	return string(b), true
}

func stripLeadingControlBytes(b []byte) []byte {
	i := 0
	for i < len(b) && b[i] < 0x20 {
		i++
	}
	return bytes.Clone(b[i:])
}
