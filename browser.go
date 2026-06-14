package sweetcookie

import (
	"context"
	"fmt"
)

func readFromBrowser(ctx context.Context, b Browser, origins []requestOrigin, opts Options) ([]Cookie, []string, error) {
	profile := ""
	if opts.Profiles != nil {
		profile = opts.Profiles[b]
	}

	switch b {
	case BrowserChrome, BrowserChromium, BrowserEdge, BrowserBrave, BrowserVivaldi, BrowserOpera,
		BrowserArc, BrowserHelium, BrowserDia, BrowserComet, BrowserAtlas, BrowserWhale:
		return readChromiumCookies(ctx, chromiumVendorForBrowser(b), profile, origins, opts)
	case BrowserFirefox, BrowserZen, BrowserFloorp, BrowserWaterfox, BrowserLibreWolf:
		return readFirefoxCookies(ctx, b, profile, origins, opts)
	case BrowserSafari:
		return readSafariCookies(ctx, profile, origins, opts)
	case BrowserInline:
		return nil, nil, nil
	default:
		return nil, []string{fmt.Sprintf("sweetcookie: unsupported browser %q", b)}, nil
	}
}
