//go:build linux && !android

package sweetcookie

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeLinuxFirefoxProfile(t *testing.T, root, label string) {
	t.Helper()
	profile := filepath.Join(root, "profile")
	if err := os.MkdirAll(profile, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "profiles.ini"), []byte("[Profile0]\nName=fixture\nIsRelative=1\nPath=profile\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	db := openTestSQLite(t, filepath.Join(profile, "cookies.sqlite"))
	if _, err := db.Exec(`CREATE TABLE moz_cookies(host TEXT, name TEXT, value TEXT, path TEXT, expiry INTEGER, isSecure INTEGER, isHttpOnly INTEGER, sameSite INTEGER, originAttributes TEXT)`); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"sid", "source-" + label} {
		if _, err := db.Exec(`INSERT INTO moz_cookies VALUES(?,?,?,?,?,?,?,?,?)`, ".example.com", name, label, "/", time.Now().Add(time.Hour).Unix(), 1, 1, 2, ""); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
}

func getLinuxFirefox(t *testing.T) map[string]string {
	t.Helper()
	result, err := Get(context.Background(), Options{URL: "https://example.com/", Browsers: []Browser{BrowserFirefox}})
	if err != nil {
		t.Fatal(err)
	}
	cookies := make(map[string]string)
	for _, cookie := range result.Cookies {
		cookies[cookie.Name] = cookie.Value
	}
	return cookies
}

func TestGetFirefoxLinuxInstallations(t *testing.T) {
	cases := []struct {
		name string
		path string
		xdg  string
	}{
		{"snap", "snap/firefox/common/.mozilla/firefox", ""},
		{"flatpak", ".var/app/org.mozilla.firefox/.mozilla/firefox", ""},
		{"xdg", "custom-config/mozilla/firefox", "custom-config"},
		{"default-xdg", ".config/mozilla/firefox", ""},
		{"relative-xdg", ".config/mozilla/firefox", "relative"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			xdg := tc.xdg
			if xdg == "custom-config" {
				xdg = filepath.Join(home, xdg)
			}
			t.Setenv("XDG_CONFIG_HOME", xdg)
			if err := os.MkdirAll(filepath.Join(home, ".mozilla", "firefox"), 0o755); err != nil {
				t.Fatal(err)
			}
			writeLinuxFirefoxProfile(t, filepath.Join(home, filepath.FromSlash(tc.path)), tc.name)
			cookies := getLinuxFirefox(t)
			if cookies["sid"] != tc.name || len(cookies) != 2 {
				t.Fatalf("installation was not read: %v", cookies)
			}
		})
	}
}

func TestGetFirefoxLinuxPreservesLegacyPrecedence(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "custom-config"))
	roots := map[string]string{
		"legacy":  ".mozilla/firefox",
		"snap":    "snap/firefox/common/.mozilla/firefox",
		"flatpak": ".var/app/org.mozilla.firefox/.mozilla/firefox",
		"xdg":     "custom-config/mozilla/firefox",
	}
	for label, root := range roots {
		writeLinuxFirefoxProfile(t, filepath.Join(home, filepath.FromSlash(root)), label)
	}
	cookies := getLinuxFirefox(t)
	if cookies["sid"] != "legacy" || len(cookies) != 5 {
		t.Fatalf("legacy precedence or multi-root discovery changed: %v", cookies)
	}
	for label := range roots {
		if cookies["source-"+label] != label {
			t.Fatalf("missing installation %s", label)
		}
	}
}
