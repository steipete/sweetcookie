package sweetcookie

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestFirefoxContainerFromOriginAttributes(t *testing.T) {
	names := map[int]string{1: "Personal", 2: "Work"}
	cases := []struct {
		in       string
		wantID   int
		wantName string
	}{
		{"", 0, ""},
		{"^userContextId=0", 0, ""},
		{"^userContextId=2", 2, "Work"},
		{"^userContextId=1&firstPartyDomain=example.com", 1, "Personal"},
		{"^userContextId=9", 9, ""}, // id without a name mapping
		{"^firstPartyDomain=example.com", 0, ""},
		{"garbage", 0, ""},
	}
	for _, c := range cases {
		got := firefoxContainerFromOriginAttributes(c.in, names)
		if got.ID != c.wantID || got.Name != c.wantName {
			t.Fatalf("origin %q: want {%d %q} got {%d %q}", c.in, c.wantID, c.wantName, got.ID, got.Name)
		}
	}
}

func TestFirefoxLoadContainers(t *testing.T) {
	dir := t.TempDir()
	json := `{"version":5,"identities":[
		{"userContextId":1,"name":"Personal","icon":"fingerprint","color":"blue"},
		{"userContextId":2,"name":"Work","icon":"briefcase","color":"orange"},
		{"userContextId":3,"icon":"cart","color":"pink"}
	]}`
	if err := os.WriteFile(filepath.Join(dir, "containers.json"), []byte(json), 0o644); err != nil {
		t.Fatal(err)
	}
	m := firefoxLoadContainers(dir)
	if m[1] != "Personal" || m[2] != "Work" {
		t.Fatalf("unexpected container map: %v", m)
	}
	if _, ok := m[3]; ok {
		t.Fatalf("entry without name should be skipped: %v", m)
	}

	// Missing file -> nil, no panic.
	if got := firefoxLoadContainers(t.TempDir()); got != nil {
		t.Fatalf("want nil for missing containers.json, got %v", got)
	}
}

func TestGet_Firefox_MultiAccountContainers(t *testing.T) {
	home := t.TempDir()
	var root string
	switch runtime.GOOS {
	case "darwin":
		t.Setenv("HOME", home)
		root = filepath.Join(home, "Library", "Application Support", "Firefox")
	case "linux":
		t.Setenv("HOME", home)
		root = filepath.Join(home, ".mozilla", "firefox")
	case "windows":
		t.Setenv("APPDATA", filepath.Join(home, "AppData", "Roaming"))
		root = filepath.Join(home, "AppData", "Roaming", "Mozilla", "Firefox")
	default:
		t.Skip("unsupported OS for firefox root discovery")
	}

	profileDir := filepath.Join(root, "Profiles", "abcd.default-release")
	if err := os.MkdirAll(profileDir, 0o755); err != nil {
		t.Fatal(err)
	}
	ini := []byte("[Profile0]\nName=default\nIsRelative=1\nPath=Profiles/abcd.default-release\n\n")
	if err := os.WriteFile(filepath.Join(root, "profiles.ini"), ini, 0o644); err != nil {
		t.Fatal(err)
	}
	containers := `{"identities":[{"userContextId":1,"name":"Personal"},{"userContextId":2,"name":"Work"}]}`
	if err := os.WriteFile(filepath.Join(profileDir, "containers.json"), []byte(containers), 0o644); err != nil {
		t.Fatal(err)
	}

	dbPath := filepath.Join(profileDir, "cookies.sqlite")
	db := openTestSQLite(t, dbPath)
	if _, err := db.Exec(`CREATE TABLE moz_cookies(host TEXT, name TEXT, value TEXT, path TEXT, expiry INTEGER, isSecure INTEGER, isHttpOnly INTEGER, sameSite INTEGER, originAttributes TEXT)`); err != nil {
		t.Fatal(err)
	}
	expiry := time.Now().Add(24 * time.Hour).Unix()
	// Same name/domain/path across three containers must survive dedupe.
	rows := []struct {
		value, oa string
	}{
		{"default", ""},
		{"personal", "^userContextId=1"},
		{"work", "^userContextId=2"},
	}
	for _, r := range rows {
		if _, err := db.Exec(
			`INSERT INTO moz_cookies(host,name,value,path,expiry,isSecure,isHttpOnly,sameSite,originAttributes) VALUES(?,?,?,?,?,?,?,?,?)`,
			".example.com", "sid", r.value, "/", expiry, 1, 1, 2, r.oa,
		); err != nil {
			t.Fatal(err)
		}
	}

	res, err := Get(context.Background(), Options{
		URL:      "https://app.example.com/",
		Browsers: []Browser{BrowserFirefox},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Cookies) != 3 {
		t.Fatalf("want 3 container cookies got %d (warnings=%v)", len(res.Cookies), res.Warnings)
	}

	byID := map[int]Cookie{}
	for _, c := range res.Cookies {
		byID[c.Container.ID] = c
	}
	if c, ok := byID[0]; !ok || c.Value != "default" || c.Container.Name != "" {
		t.Fatalf("default container cookie wrong: %+v", c)
	}
	if c, ok := byID[1]; !ok || c.Value != "personal" || c.Container.Name != "Personal" {
		t.Fatalf("container 1 cookie wrong: %+v", c)
	}
	if c, ok := byID[2]; !ok || c.Value != "work" || c.Container.Name != "Work" {
		t.Fatalf("container 2 cookie wrong: %+v", c)
	}
}
