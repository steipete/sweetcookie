//go:build !darwin || ios

package sweetcookie

import "context"

func readSafariCookies(_ context.Context, _ string, _ []requestOrigin, _ Options) ([]Cookie, []string, error) {
	return nil, []string{"sweetcookie: Safari supported on macOS only"}, nil
}
