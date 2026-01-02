# sweetcookie

Go library to load cookies from local browser profiles.

## Supported browsers

- Chromium-family: Chrome, Chromium, Microsoft Edge, Brave, Vivaldi, Opera (macOS / Windows / Linux)
- Firefox (macOS / Windows / Linux)
- Safari (macOS only; reads `Cookies.binarycookies`)

## Usage

```go
package main

import (
	"context"
	"fmt"

	"github.com/steipete/sweetcookie"
)

func main() {
	res, err := sweetcookie.Get(context.Background(), sweetcookie.Options{
		URL:      "https://example.com/",
		Names:    []string{"session", "csrf"},
		Browsers: []sweetcookie.Browser{sweetcookie.BrowserChrome, sweetcookie.BrowserFirefox},
		Mode:     sweetcookie.ModeMerge,
	})
	if err != nil {
		panic(err)
	}
	for _, w := range res.Warnings {
		fmt.Println("warn:", w)
	}
	for _, c := range res.Cookies {
		fmt.Println(c.Source.Browser, c.Domain, c.Name, c.Value)
	}
}
```

Inline cookies (escape hatch for locked DBs / new encryption schemes):

```go
res, _ := sweetcookie.Get(context.Background(), sweetcookie.Options{
	URL: "https://example.com/",
	Inline: sweetcookie.InlineCookies{
		File: "/path/to/cookies.json",
	},
	Mode: sweetcookie.ModeFirst,
})
_ = res
```

## Notes

- Chrome-family cookie DBs can be locked; sweetcookie snapshots the DB + WAL sidecars before reading.
- macOS: derives legacy Chromium AES-128-CBC key from Keychain “Safe Storage” password via `security`.
- Windows: uses DPAPI to unwrap the Chromium master key from `Local State` and decrypts AES-256-GCM cookie values.
- Linux: tries `go-keyring` first, then shells out to `secret-tool` (GNOME) or `kwallet-query` + `dbus-send` (KDE) to read “Safe Storage”.
- Some very new Chromium Windows “app-bound” cookie encryption variants are not directly decryptable without extra OS-specific plumbing; use inline cookies for those cases.

## Development

```bash
make ci
```
