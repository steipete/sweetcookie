package sweetcookie

import (
	"testing"
	"time"
)

func TestCookieMatchesOrigin_DomainAndPathAndSecure(t *testing.T) {
	o := requestOrigin{scheme: "https", host: "app.example.com", path: "/a/b"}
	c := Cookie{Name: "sid", Value: "x", Domain: "example.com", Path: "/a", Secure: true}

	if !cookieMatchesOrigin(c, o) {
		t.Fatalf("expected match")
	}
	c.Secure = true
	o.scheme = "http"
	if cookieMatchesOrigin(c, o) {
		t.Fatalf("expected no match for secure over http")
	}
}

func TestFilterCookies_AllowlistAndExpiry(t *testing.T) {
	expired := time.Now().Add(-time.Hour)
	cookies := []Cookie{
		{Name: "a", Value: "1", Domain: "example.com", Path: "/", Expires: &expired},
		{Name: "b", Value: "2", Domain: "example.com", Path: "/"},
	}

	origins, err := normalizeOrigins("https://example.com/", nil, false)
	if err != nil {
		t.Fatal(err)
	}

	allow := map[string]struct{}{"b": {}}
	filtered := filterCookies(origins, allow, false, cookies)
	if len(filtered) != 1 || filtered[0].Name != "b" {
		t.Fatalf("unexpected filtered: %#v", filtered)
	}
}

func TestDedupeCookies(t *testing.T) {
	cookies := []Cookie{
		{Name: "a", Domain: "example.com", Path: "/", Value: "1"},
		{Name: "a", Domain: "example.com", Path: "/", Value: "2"},
	}
	out := dedupeCookies(cookies)
	if len(out) != 1 {
		t.Fatalf("want 1 got %d", len(out))
	}
	if out[0].Value != "1" {
		t.Fatalf("keeps first")
	}
}
