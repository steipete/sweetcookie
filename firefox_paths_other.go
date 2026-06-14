//go:build !darwin && !linux && !windows

package sweetcookie

func firefoxRoots(_ Browser) []string { return nil }
