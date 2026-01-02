//go:build darwin && !ios

package sweetcookie

import (
	"context"
	"fmt"
	"strings"
	"time"
)

func chromiumDecryptor(vendor chromiumVendor, _ []chromiumStore, timeout time.Duration) (chromiumDecryptFunc, []string) {
	password, err := macosReadKeychainPassword(timeout, vendor.safeStorageService, vendor.safeStorageAccount)
	if err != nil {
		return nil, []string{fmt.Sprintf("sweetcookie: macOS keychain read failed (%s): %v", vendor.safeStorageService, err)}
	}
	password = strings.TrimSpace(password)
	if password == "" {
		return nil, []string{fmt.Sprintf("sweetcookie: macOS keychain returned an empty %s password", vendor.safeStorageService)}
	}

	key := chromiumDeriveAESCBCKey(password, chromiumAESCBCIterationsMacOS)
	return func(encrypted []byte, metaVersion int64) ([]byte, bool) {
		plain, err := chromiumDecryptAESCBC(encrypted, key, metaVersion, true)
		return plain, err == nil
	}, nil
}

func macosReadKeychainPassword(timeout time.Duration, service string, account string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	stdout, stderr, err := execCapture(ctx, "security", []string{
		"find-generic-password",
		"-w",
		"-a", account,
		"-s", service,
	})
	if err != nil {
		if stderr != "" {
			return "", fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr))
		}
		return "", err
	}
	return strings.TrimSpace(stdout), nil
}
