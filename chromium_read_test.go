package sweetcookie

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestGet_ChromiumFamily_ExplicitDB(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("keychain stub test only implemented for darwin")
	}

	// Stub `security` in PATH to avoid touching the real keychain.
	binDir := t.TempDir()
	securityPath := filepath.Join(binDir, "security")
	if err := os.WriteFile(securityPath, []byte("#!/bin/sh\necho pw\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+":"+os.Getenv("PATH"))

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "Cookies")
	db := openTestSQLite(t, dbPath)
	if _, err := db.Exec(`CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO meta(key,value) VALUES('version','30')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE cookies(host_key TEXT, name TEXT, path TEXT, value TEXT, encrypted_value BLOB, expires_utc INTEGER, is_secure INTEGER, is_httponly INTEGER, samesite INTEGER)`); err != nil {
		t.Fatal(err)
	}

	key := chromiumDeriveAESCBCKey("pw", chromiumAESCBCIterationsMacOS)
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

	res, err := Get(context.Background(), Options{
		URL:      "https://app.example.com/a",
		Browsers: []Browser{BrowserChrome},
		Profiles: map[Browser]string{BrowserChrome: dbPath},
	})
	if err != nil {
		t.Fatal(err)
	}
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
