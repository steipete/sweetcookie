package sweetcookie

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestGet_ChromiumFamily_ExplicitDB(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("keychain stub test only implemented for darwin")
	}

	t.Setenv("GOOKIE_CHROME_SAFE_STORAGE_PASSWORD", "")

	// Stub `security` in PATH to avoid touching the real keychain.
	binDir := t.TempDir()
	securityPath := filepath.Join(binDir, "security")
	if err := os.WriteFile(securityPath, []byte("#!/bin/sh\necho pw\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+":"+os.Getenv("PATH"))

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "Cookies")
	writeTestChromiumCookieDB(t, dbPath, "pw")

	res, err := Get(context.Background(), Options{
		URL:      "https://app.example.com/a",
		Browsers: []Browser{BrowserChrome},
		Profiles: map[Browser]string{BrowserChrome: dbPath},
	})
	if err != nil {
		t.Fatal(err)
	}
	assertTestChromiumCookies(t, res)
}

func TestGet_HeliumExplicitBrowserReadsDiscoveredProfileWithEnvOverride(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS Chromium profile layout/decryptor test")
	}

	// The override must avoid a Keychain prompt during deterministic runs.
	binDir := t.TempDir()
	securityPath := filepath.Join(binDir, "security")
	if err := os.WriteFile(securityPath, []byte("#!/bin/sh\necho keychain should not be used >&2\nexit 44\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+":"+os.Getenv("PATH"))
	t.Setenv("GOOKIE_HELIUM_SAFE_STORAGE_PASSWORD", "pw")

	home := t.TempDir()
	t.Setenv("HOME", home)
	userDataDir := filepath.Join(home, "Library", "Application Support", "net.imput.helium")
	networkDir := filepath.Join(userDataDir, "Default", "Network")
	if err := os.MkdirAll(networkDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(userDataDir, "Local State"), []byte(`{"profile":{"info_cache":{"Default":{"is_using_default_name":true,"name":"Default"}}}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(networkDir, "Cookies")
	writeTestChromiumCookieDB(t, dbPath, "pw")

	res, err := Get(context.Background(), Options{
		URL:      "https://app.example.com/a",
		Browsers: []Browser{BrowserHelium},
	})
	if err != nil {
		t.Fatal(err)
	}
	assertTestChromiumCookies(t, res)
	for _, c := range res.Cookies {
		if c.Source.Browser != BrowserHelium || c.Source.Profile != "Default" || c.Source.StorePath != dbPath {
			t.Fatalf("unexpected Helium source: %#v", c.Source)
		}
	}
}

func TestChromiumDecryptor_HeliumKeychainServiceAccount(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS keychain command test")
	}

	t.Setenv("GOOKIE_HELIUM_SAFE_STORAGE_PASSWORD", "")
	binDir := t.TempDir()
	argsPath := filepath.Join(t.TempDir(), "args")
	securityPath := filepath.Join(binDir, "security")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$SECURITY_ARGS_FILE\"\necho pw\n"
	if err := os.WriteFile(securityPath, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+":"+os.Getenv("PATH"))
	t.Setenv("SECURITY_ARGS_FILE", argsPath)

	decrypt, warnings := chromiumDecryptor(chromiumVendorForBrowser(BrowserHelium), nil, time.Second)
	if decrypt == nil || len(warnings) != 0 {
		t.Fatalf("unexpected decryptor result: decrypt=%v warnings=%v", decrypt != nil, warnings)
	}

	gotBytes, err := os.ReadFile(argsPath)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Split(strings.TrimSpace(string(gotBytes)), "\n")
	want := []string{"find-generic-password", "-w", "-a", "Helium", "-s", "Helium Storage Key"}
	if len(got) != len(want) {
		t.Fatalf("want args %v got %v", want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("want args %v got %v", want, got)
		}
	}
}

func writeTestChromiumCookieDB(t *testing.T, dbPath string, password string) {
	t.Helper()

	db := openTestSQLite(t, dbPath)
	defer func() { _ = db.Close() }()
	if _, err := db.Exec(`CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO meta(key,value) VALUES('version','30')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE cookies(host_key TEXT, name TEXT, path TEXT, value TEXT, encrypted_value BLOB, expires_utc INTEGER, is_secure INTEGER, is_httponly INTEGER, samesite INTEGER)`); err != nil {
		t.Fatal(err)
	}

	key := chromiumDeriveAESCBCKey(password, chromiumAESCBCIterationsMacOS)
	plain := append(make([]byte, 32), []byte("hello")...)
	enc := encryptAESCBCForTest(t, "v10", key, plain)

	expires := time.Now().Add(24 * time.Hour).UTC()
	expiresUTC := timeToChromiumExpiresUTC(expires)

	if _, err := db.Exec(
		`INSERT INTO cookies(host_key,name,path,value,encrypted_value,expires_utc,is_secure,is_httponly,samesite) VALUES(?,?,?,?,?,?,?,?,?)`,
		".example.com", "sid", "/", "", enc, expiresUTC, 1, 1, 1,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(
		`INSERT INTO cookies(host_key,name,path,value,encrypted_value,expires_utc,is_secure,is_httponly,samesite) VALUES(?,?,?,?,?,?,?,?,?)`,
		".example.com", "plain", "/", "", []byte("plaintext"), expiresUTC, 0, 0, 0,
	); err != nil {
		t.Fatal(err)
	}
}

func assertTestChromiumCookies(t *testing.T, res Result) {
	t.Helper()

	if len(res.Cookies) != 2 {
		t.Fatalf("want 2 cookies got %d (warnings=%v)", len(res.Cookies), res.Warnings)
	}

	got := map[string]string{}
	for _, c := range res.Cookies {
		got[c.Name] = c.Value
	}
	if got["sid"] != "hello" {
		t.Fatalf("want sid=%q got %q", "hello", got["sid"])
	}
	if got["plain"] != "plaintext" {
		t.Fatalf("want plain=%q got %q", "plaintext", got["plain"])
	}
}

func timeToChromiumExpiresUTC(t time.Time) int64 {
	const unixEpochDiffMicros = int64(11644473600000000)
	return unixEpochDiffMicros + (t.UnixNano() / 1000)
}
