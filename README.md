# sweetcookie 🍪 — cookies from every browser jar

[![CI](https://img.shields.io/github/actions/workflow/status/steipete/sweetcookie/ci.yml?branch=main&style=flat-square&label=ci)](https://github.com/steipete/sweetcookie/actions/workflows/ci.yml)
[![GitHub release](https://img.shields.io/github/v/release/steipete/sweetcookie?style=flat-square)](https://github.com/steipete/sweetcookie/releases/latest)
[![Go](https://img.shields.io/badge/Go-1.25%2B-00ADD8?style=flat-square&logo=go&logoColor=white)](https://go.dev/)
[![License](https://img.shields.io/github/license/steipete/sweetcookie?style=flat-square)](LICENSE)

Sweetcookie is a Go library for local tools that read, decrypt, filter, and deduplicate cookies from Chromium-family browsers, Firefox-family browsers, Safari on macOS, and JSON input. It reads local browser state and may trigger keychain or keyring prompts, so it is intended for CLI helpers, development scripts, and test harnesses on macOS, Windows, and Linux rather than servers.

## Install

```sh
go get github.com/steipete/sweetcookie@latest
```

Sweetcookie requires Go 1.25 or newer.

## Quick start

This example uses an inline cookie so it runs without browser access while exercising the same origin filtering and result API:

```go
package main

import (
	"context"
	"fmt"

	"github.com/steipete/sweetcookie"
)

func main() {
	result, err := sweetcookie.Get(context.Background(), sweetcookie.Options{
		URL:      "https://example.com/account",
		Browsers: []sweetcookie.Browser{sweetcookie.BrowserInline},
		Inline: sweetcookie.InlineCookies{JSON: []byte(
			`[{"name":"session","value":"ready","domain":"example.com","path":"/"}]`,
		)},
	})
	if err != nil {
		panic(err)
	}

	for _, cookie := range result.Cookies {
		fmt.Printf("%s=%s (%s)\n", cookie.Name, cookie.Value, cookie.Source.Browser)
	}
}
```

```console
$ go run .
session=ready (inline)
```

For browser profiles, omit `Inline` and `Browsers` to try the default browser order, or choose sources explicitly:

```go
result, err := sweetcookie.Get(context.Background(), sweetcookie.Options{
	URL:      "https://example.com/",
	Names:    []string{"session", "csrf"},
	Browsers: []sweetcookie.Browser{sweetcookie.BrowserChrome, sweetcookie.BrowserFirefox},
	Mode:     sweetcookie.ModeMerge,
})
```

`result.Cookies` contains matching cookies and their source metadata. Browser-specific failures are returned in `result.Warnings` so one unavailable profile does not prevent other sources from succeeding.

## Supported browsers

| Browsers | Platforms |
| --- | --- |
| Chrome, Chromium, Microsoft Edge, Brave, Vivaldi, Opera, Whale | macOS, Windows, Linux |
| Arc, Comet | macOS, Windows |
| Dia, ChatGPT Atlas | macOS |
| Helium | macOS; explicit opt-in |
| Firefox, Zen, Floorp, Waterfox, LibreWolf | macOS, Windows, Linux |
| Safari | macOS |

Helium is not part of `DefaultBrowsers()`; request it with `BrowserHelium`. Firefox Multi-Account Container metadata is exposed through `Cookie.Container`: `ID` is Firefox's `userContextId`, and `Name` comes from `containers.json`. Cookies from different containers remain distinct.

## Selecting cookies and profiles

`Get` matches cookie domains, paths, secure schemes, names, and expiry against the requested origins. The main options are:

| Option | Purpose |
| --- | --- |
| `URL`, `Origins` | Select cookies for one or more destinations. |
| `Names` | Limit results to specific cookie names. |
| `Browsers` | Set the source order; an empty list uses `DefaultBrowsers()`. |
| `Profiles` | Select a profile name, profile directory, or cookie database per browser. |
| `ModeMerge` | Read all requested sources and deduplicate the result. |
| `ModeFirst` | Stop after the first source that returns cookies. |
| `Inline` | Read cookie JSON from bytes, base64, or a file before browser profiles. |
| `IncludeExpired` | Keep expired cookies in the result. |
| `AllowAllHosts` | Permit calls without `URL` or `Origins`. |
| `Timeout` | Limit operating-system credential helper calls. |

Inline input accepts either a cookie array or an object with a `cookies` array. Use it when a browser database is locked or an encryption scheme is unavailable. The full API is documented on [pkg.go.dev](https://pkg.go.dev/github.com/steipete/sweetcookie).

## Browser access

Sweetcookie snapshots Chromium and Firefox cookie databases together with their WAL sidecars before reading, so the original browser data stays untouched.

Chromium cookie decryption follows each platform's credential system:

- On macOS, it reads the browser's Safe Storage password from Keychain and derives the legacy AES-128-CBC key.
- On Windows, it unwraps the master key from `Local State` with DPAPI and decrypts AES-256-GCM values.
- On Linux, it tries `go-keyring`, then `secret-tool` for GNOME or `kwallet-query` with `dbus-send` for KDE.

On macOS and Linux, per-browser environment variables such as `GOOKIE_CHROME_SAFE_STORAGE_PASSWORD` and `GOOKIE_HELIUM_SAFE_STORAGE_PASSWORD` can supply the Safe Storage password for deterministic local tooling. Some recent Chromium builds on Windows use app-bound encryption that requires additional OS-specific access; use inline cookies when those values cannot be decrypted.

Safari reads `Cookies.binarycookies` on macOS. Profile paths can be overridden through `Options.Profiles` when automatic discovery does not match the desired browser profile.

## Development

```sh
go test ./...
make ci
```

`make ci` checks formatting, lint, tests, and the coverage threshold.
Development uses Go 1.25.14 through the `go.mod` toolchain directive. CI tests
that patch on macOS, Windows, and Linux, plus Go 1.25.0 on Linux to verify the
supported source minimum.

## License

MIT. See [LICENSE](LICENSE).
