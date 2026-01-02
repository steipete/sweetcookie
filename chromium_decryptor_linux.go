//go:build linux && !android

package sweetcookie

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/zalando/go-keyring"
)

type linuxKeyringBackend string

const (
	linuxKeyringGnome   linuxKeyringBackend = "gnome"
	linuxKeyringKWallet linuxKeyringBackend = "kwallet"
	linuxKeyringBasic   linuxKeyringBackend = "basic"
)

func chromiumDecryptor(vendor chromiumVendor, _ []chromiumStore, timeout time.Duration) (chromiumDecryptFunc, []string) {
	password, warnings := linuxChromiumSafeStoragePassword(vendor, timeout)

	v10Key := chromiumDeriveAESCBCKey("peanuts", chromiumAESCBCIterationsLinux)
	emptyKey := chromiumDeriveAESCBCKey("", chromiumAESCBCIterationsLinux)
	v11Key := chromiumDeriveAESCBCKey(password, chromiumAESCBCIterationsLinux)

	return func(encrypted []byte, metaVersion int64) ([]byte, bool) {
		if len(encrypted) < 3 {
			return nil, false
		}
		prefix := string(encrypted[:3])
		switch prefix {
		case "v10":
			for _, key := range [][]byte{v10Key, emptyKey} {
				plain, err := chromiumDecryptAESCBC(encrypted, key, metaVersion, false)
				if err == nil {
					return plain, true
				}
			}
			return nil, false
		case "v11":
			for _, key := range [][]byte{v11Key, emptyKey} {
				plain, err := chromiumDecryptAESCBC(encrypted, key, metaVersion, false)
				if err == nil {
					return plain, true
				}
			}
			return nil, false
		default:
			return nil, false
		}
	}, warnings
}

func linuxChromiumSafeStoragePassword(vendor chromiumVendor, timeout time.Duration) (password string, warnings []string) {
	// Escape hatch for deterministic tooling/CI.
	if override := strings.TrimSpace(os.Getenv(envKeySafeStoragePassword(vendor.browser))); override != "" {
		return override, nil
	}

	backend := parseLinuxKeyringBackend()
	if backend == "" {
		backend = chooseLinuxKeyringBackend()
	}

	switch backend {
	case linuxKeyringBasic:
		return "", nil
	case linuxKeyringGnome:
		if pw, err := keyring.Get(vendor.safeStorageService, vendor.safeStorageAccount); err == nil && strings.TrimSpace(pw) != "" {
			return strings.TrimSpace(pw), nil
		}
		pw, err := linuxSecretToolLookup(timeout, vendor.safeStorageService, vendor.safeStorageAccount)
		if err == nil {
			return pw, nil
		}
		warnings = append(warnings, "sweetcookie: failed to read Linux keyring via secret-tool; v11 cookies may be unavailable")
		return "", warnings
	case linuxKeyringKWallet:
		pw, err := linuxKWalletLookup(timeout, vendor.safeStorageService, vendor.safeStorageAccount)
		if err == nil {
			return pw, nil
		}
		warnings = append(warnings, "sweetcookie: failed to read Linux keyring via kwallet-query; v11 cookies may be unavailable")
		return "", warnings
	default:
		return "", []string{fmt.Sprintf("sweetcookie: unknown Linux keyring backend %q", backend)}
	}
}

func parseLinuxKeyringBackend() linuxKeyringBackend {
	raw := strings.ToLower(strings.TrimSpace(os.Getenv("GOOKIE_LINUX_KEYRING")))
	switch raw {
	case "gnome":
		return linuxKeyringGnome
	case "kwallet":
		return linuxKeyringKWallet
	case "basic":
		return linuxKeyringBasic
	default:
		return ""
	}
}

func chooseLinuxKeyringBackend() linuxKeyringBackend {
	xdg := strings.ToLower(os.Getenv("XDG_CURRENT_DESKTOP"))
	for _, p := range strings.Split(xdg, ":") {
		if strings.TrimSpace(p) == "kde" {
			return linuxKeyringKWallet
		}
	}
	if os.Getenv("KDE_FULL_SESSION") != "" {
		return linuxKeyringKWallet
	}
	return linuxKeyringGnome
}

func linuxSecretToolLookup(timeout time.Duration, service string, account string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	stdout, _, err := execCapture(ctx, "secret-tool", []string{"lookup", "service", service, "account", account})
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(stdout), nil
}

func linuxKWalletLookup(timeout time.Duration, service string, account string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	wallet := "kdewallet"
	serviceName, walletPath := linuxKWalletServiceNameAndPath()
	if serviceName != "" && walletPath != "" {
		stdout, _, err := execCapture(ctx, "dbus-send", []string{
			"--session",
			"--print-reply=literal",
			"--dest=" + serviceName,
			walletPath,
			"org.kde.KWallet.networkWallet",
		})
		if err == nil {
			if w := strings.TrimSpace(strings.ReplaceAll(stdout, "\"", "")); w != "" {
				wallet = w
			}
		}
	}

	folder := account + " Keys"
	stdout, _, err := execCapture(ctx, "kwallet-query", []string{"--read-password", service, "--folder", folder, wallet})
	if err != nil {
		return "", err
	}
	out := strings.TrimSpace(stdout)
	if strings.HasPrefix(strings.ToLower(out), "failed to read") {
		return "", fmt.Errorf("kwallet-query failed")
	}
	return out, nil
}

func linuxKWalletServiceNameAndPath() (serviceName string, walletPath string) {
	switch strings.TrimSpace(os.Getenv("KDE_SESSION_VERSION")) {
	case "6":
		return "org.kde.kwalletd6", "/modules/kwalletd6"
	case "5":
		return "org.kde.kwalletd5", "/modules/kwalletd5"
	default:
		return "org.kde.kwalletd", "/modules/kwalletd"
	}
}
