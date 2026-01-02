package sweetcookie

import (
	"encoding/base64"
	"os"
	"testing"
)

func TestReadInlineCookies_JSONArray(t *testing.T) {
	raw := []byte(`[{"name":"a","value":"b","domain":"example.com","path":"/","secure":true,"httpOnly":true,"sameSite":"Lax","expires":1735689600}]`)
	cookies, warnings, err := readInlineCookies(InlineCookies{JSON: raw})
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", warnings)
	}
	if len(cookies) != 1 {
		t.Fatalf("want 1 cookie got %d", len(cookies))
	}
	if cookies[0].Source.Browser != BrowserInline {
		t.Fatalf("want source inline got %q", cookies[0].Source.Browser)
	}
	if cookies[0].SameSite != SameSiteLax {
		t.Fatalf("want SameSite Lax got %q", cookies[0].SameSite)
	}
	if cookies[0].Expires == nil {
		t.Fatalf("expected expires")
	}
}

func TestReadInlineCookies_Base64AndFile(t *testing.T) {
	raw := []byte(`{"cookies":[{"name":"a","value":"b","domain":"example.com","path":"/"}]}`)
	b64 := base64.StdEncoding.EncodeToString(raw)
	cookies, _, err := readInlineCookies(InlineCookies{Base64: b64})
	if err != nil {
		t.Fatal(err)
	}
	if len(cookies) != 1 {
		t.Fatalf("want 1 got %d", len(cookies))
	}

	dir := t.TempDir()
	p := dir + "/cookies.json"
	if err := os.WriteFile(p, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	cookies, _, err = readInlineCookies(InlineCookies{File: p})
	if err != nil {
		t.Fatal(err)
	}
	if len(cookies) != 1 {
		t.Fatalf("want 1 got %d", len(cookies))
	}
}
