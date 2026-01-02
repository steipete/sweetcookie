//go:build darwin && !ios

package sweetcookie

import (
	"context"
	"path/filepath"
	"testing"
)

func TestSafariReadBinaryCookies_ContextCanceled(t *testing.T) {
	p := filepath.Join(t.TempDir(), "Cookies.binarycookies")
	writeSafariBinaryCookies(t, p)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := safariReadBinaryCookies(ctx, p, false)
	if err == nil {
		t.Fatal("expected error")
	}
}
