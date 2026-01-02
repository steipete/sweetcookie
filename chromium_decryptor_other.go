//go:build !darwin && !linux && !windows

package sweetcookie

import "time"

func chromiumDecryptor(_ chromiumVendor, _ []chromiumStore, _ time.Duration) (chromiumDecryptFunc, []string) {
	return nil, []string{"sweetcookie: chromium cookie decryption unsupported on this OS"}
}
