package sweetcookie

import (
	"context"
	"runtime"
	"strings"
	"testing"
)

func TestChromiumVendorForBrowser_Community(t *testing.T) {
	cases := map[Browser]struct{ service, account string }{
		BrowserDia:   {"Dia Safe Storage", "Dia"},
		BrowserComet: {"Comet Safe Storage", "Comet"},
		BrowserAtlas: {"ChatGPT Safe Storage", "ChatGPT"},
		BrowserWhale: {"Whale Safe Storage", "Whale"},
	}
	for b, want := range cases {
		v := chromiumVendorForBrowser(b)
		if v.safeStorageService != want.service || v.safeStorageAccount != want.account {
			t.Fatalf("%s: want (%q,%q) got (%q,%q)", b, want.service, want.account, v.safeStorageService, v.safeStorageAccount)
		}
	}
}

func TestChromiumUserDataDirs_CommunityDarwin(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin-only paths")
	}
	cases := map[Browser]string{
		BrowserDia:   "/Dia/User Data",
		BrowserComet: "/Comet/User Data",
		BrowserAtlas: "/com.openai.atlas.web",
		BrowserWhale: "/Naver/Whale",
	}
	for b, suffix := range cases {
		dirs := chromiumUserDataDirs(b)
		if len(dirs) != 1 || !strings.HasSuffix(dirs[0], suffix) {
			t.Fatalf("%s: want suffix %q got %v", b, suffix, dirs)
		}
	}
}

func TestFirefoxRoots_Forks(t *testing.T) {
	for _, b := range []Browser{BrowserFirefox, BrowserZen, BrowserFloorp, BrowserWaterfox, BrowserLibreWolf} {
		if got := firefoxRoots(b); len(got) == 0 {
			switch runtime.GOOS {
			case "darwin", "linux", "windows":
				t.Fatalf("%s: expected at least one root", b)
			}
		}
	}
}

func TestReadFromBrowser_CommunityRouted(t *testing.T) {
	for _, b := range []Browser{BrowserDia, BrowserComet, BrowserAtlas, BrowserWhale, BrowserZen, BrowserFloorp, BrowserWaterfox, BrowserLibreWolf} {
		_, warnings, err := readFromBrowser(context.Background(), b, nil, Options{})
		if err != nil {
			t.Fatalf("%s: unexpected error %v", b, err)
		}
		for _, w := range warnings {
			if strings.Contains(w, "unsupported browser") {
				t.Fatalf("%s: should be routed, got %q", b, w)
			}
		}
	}
}
