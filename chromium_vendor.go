package sweetcookie

import "fmt"

type chromiumVendor struct {
	browser Browser

	// user-visible
	label string

	// "Safe Storage" secret identifier.
	safeStorageService string
	safeStorageAccount string
}

func chromiumVendorForBrowser(b Browser) chromiumVendor {
	//nolint:exhaustive // Only Chromium-family browsers are mapped here.
	switch b {
	case BrowserChrome:
		return chromiumVendor{browser: b, label: "Chrome", safeStorageService: "Chrome Safe Storage", safeStorageAccount: "Chrome"}
	case BrowserChromium:
		return chromiumVendor{browser: b, label: "Chromium", safeStorageService: "Chromium Safe Storage", safeStorageAccount: "Chromium"}
	case BrowserEdge:
		return chromiumVendor{browser: b, label: "Microsoft Edge", safeStorageService: "Microsoft Edge Safe Storage", safeStorageAccount: "Microsoft Edge"}
	case BrowserBrave:
		return chromiumVendor{browser: b, label: "Brave", safeStorageService: "Brave Safe Storage", safeStorageAccount: "Brave"}
	case BrowserVivaldi:
		return chromiumVendor{browser: b, label: "Vivaldi", safeStorageService: "Vivaldi Safe Storage", safeStorageAccount: "Vivaldi"}
	case BrowserOpera:
		return chromiumVendor{browser: b, label: "Opera", safeStorageService: "Opera Safe Storage", safeStorageAccount: "Opera"}
	case BrowserArc:
		return chromiumVendor{browser: b, label: "Arc", safeStorageService: "Arc Safe Storage", safeStorageAccount: "Arc"}
	case BrowserHelium:
		return chromiumVendor{browser: b, label: "Helium", safeStorageService: "Helium Storage Key", safeStorageAccount: "Helium"}
	case BrowserDia:
		return chromiumVendor{browser: b, label: "Dia", safeStorageService: "Dia Safe Storage", safeStorageAccount: "Dia"}
	case BrowserComet:
		return chromiumVendor{browser: b, label: "Comet", safeStorageService: "Comet Safe Storage", safeStorageAccount: "Comet"}
	case BrowserAtlas:
		return chromiumVendor{browser: b, label: "ChatGPT Atlas", safeStorageService: "ChatGPT Safe Storage", safeStorageAccount: "ChatGPT"}
	case BrowserWhale:
		return chromiumVendor{browser: b, label: "Whale", safeStorageService: "Whale Safe Storage", safeStorageAccount: "Whale"}
	default:
		return chromiumVendor{browser: b, label: string(b), safeStorageService: fmt.Sprintf("%s Safe Storage", b), safeStorageAccount: string(b)}
	}
}
