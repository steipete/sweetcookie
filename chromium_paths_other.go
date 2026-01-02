//go:build !darwin && !linux && !windows

package sweetcookie

func chromiumUserDataDirs(_ Browser) []string {
	return nil
}
