//go:build darwin && !ios

package sweetcookie

import "testing"

func TestSafariCookieFiles_OverrideNotFound(t *testing.T) {
	files, warnings := safariCookieFiles("/no/such/file")
	if len(files) != 0 || len(warnings) == 0 {
		t.Fatalf("expected warnings for missing override")
	}
}
