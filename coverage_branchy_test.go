package sweetcookie

import (
	"testing"
	"time"
)

func TestChromiumSameSiteFromInt_Branches(t *testing.T) {
	if chromiumSameSiteFromInt(2) != SameSiteStrict {
		t.Fatal("strict")
	}
	if chromiumSameSiteFromInt(1) != SameSiteLax {
		t.Fatal("lax")
	}
	if chromiumSameSiteFromInt(0) != SameSiteNone {
		t.Fatal("none")
	}
	if chromiumSameSiteFromInt(99) != "" {
		t.Fatal("unknown")
	}
}

func TestChromiumRowToCookie_Branches(t *testing.T) {
	v := chromiumVendorForBrowser(BrowserChrome)
	st := chromiumStore{cookiesDB: "x", profile: "p"}

	if _, ok := chromiumRowToCookie(v, st, chromiumCookieRow{}, 0, nil); ok {
		t.Fatal("expected false for empty row")
	}
	if _, ok := chromiumRowToCookie(v, st, chromiumCookieRow{name: "a"}, 0, nil); ok {
		t.Fatal("expected false for missing host")
	}
	if _, ok := chromiumRowToCookie(v, st, chromiumCookieRow{hostKey: "example.com"}, 0, nil); ok {
		t.Fatal("expected false for missing name")
	}

	// Value present: skips decrypt.
	c, ok := chromiumRowToCookie(v, st, chromiumCookieRow{
		hostKey: "example.com",
		name:    "a",
		path:    "",
		value:   "b",
	}, 0, nil)
	if !ok || c.Path != "/" || c.Value != "b" {
		t.Fatalf("unexpected: %#v %v", c, ok)
	}

	// Decrypt returns invalid UTF-8 -> dropped.
	_, ok = chromiumRowToCookie(v, st, chromiumCookieRow{
		hostKey:        "example.com",
		name:           "a",
		value:          "",
		encryptedValue: []byte("v10....."),
	}, 0, func(_ []byte, _ int64) ([]byte, bool) { return []byte{0xff}, true })
	if ok {
		t.Fatal("expected drop for invalid UTF-8")
	}

	// Expires conversion.
	expiresUTC := timeToChromiumExpiresUTC(time.Now().Add(time.Hour).UTC())
	c, ok = chromiumRowToCookie(v, st, chromiumCookieRow{
		hostKey:    ".example.com",
		name:       "sid",
		value:      "x",
		path:       "/",
		expiresUTC: expiresUTC,
		sameSite:   2,
	}, 0, nil)
	if !ok || c.Expires == nil || c.Domain != "example.com" || c.SameSite != SameSiteStrict {
		t.Fatalf("unexpected: %#v %v", c, ok)
	}
}

func TestExpandHostCandidates_Branches(t *testing.T) {
	if got := expandHostCandidates("localhost"); len(got) != 1 || got[0] != "localhost" {
		t.Fatalf("unexpected: %v", got)
	}
	got := expandHostCandidates("a.b.c")
	if len(got) < 2 {
		t.Fatalf("unexpected: %v", got)
	}
}

func TestPathMatchesCookiePath_TrailingSlash(t *testing.T) {
	if !pathMatchesCookiePath("/a/b", "/a/") {
		t.Fatal("expected match")
	}
	if pathMatchesCookiePath("/aX", "/a") {
		t.Fatal("expected no match")
	}
}
