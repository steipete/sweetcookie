package sweetcookie

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type chromiumStore struct {
	cookiesDB  string
	userData   string
	profile    string
	isDefault  bool
	isFallback bool
}

func readChromiumCookies(ctx context.Context, vendor chromiumVendor, profileOverride string, origins []requestOrigin, opts Options) ([]Cookie, []string, error) {
	stores, warnings := chromiumResolveStores(vendor.browser, profileOverride)
	if len(stores) == 0 {
		return nil, append(warnings, fmt.Sprintf("sweetcookie: %s cookie store not found", vendor.label)), nil
	}

	metaHosts := originsToHosts(origins)

	decrypt, decryptWarnings := chromiumDecryptor(vendor, stores, opts.Timeout)
	warnings = append(warnings, decryptWarnings...)

	var out []Cookie
	for _, st := range stores {
		snapshotPath, cleanup, snapWarnings, err := chromiumOpenSnapshotReadOnly(ctx, st.cookiesDB)
		warnings = append(warnings, snapWarnings...)
		if err != nil {
			continue
		}
		func() {
			defer cleanup()

			db, err := chromiumOpenDB(ctx, snapshotPath)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("sweetcookie: failed to open %s cookies DB: %v", vendor.label, err))
				return
			}
			defer func() { _ = db.Close() }()

			metaVersion := chromiumMetaVersion(ctx, db)

			rows, err := chromiumReadCookieRows(ctx, db, metaHosts)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("sweetcookie: failed to read %s cookies: %v", vendor.label, err))
				return
			}

			for _, row := range rows {
				c, ok := chromiumRowToCookie(vendor, st, row, metaVersion, decrypt)
				if !ok {
					continue
				}
				out = append(out, c)
			}
		}()
	}

	return out, warnings, nil
}

type chromiumDecryptFunc func(encrypted []byte, metaVersion int64) ([]byte, bool)

func chromiumRowToCookie(vendor chromiumVendor, st chromiumStore, row chromiumCookieRow, metaVersion int64, decrypt chromiumDecryptFunc) (Cookie, bool) {
	if row.name == "" {
		return Cookie{}, false
	}
	if row.hostKey == "" {
		return Cookie{}, false
	}

	value := row.value
	if value == "" && len(row.encryptedValue) > 0 && decrypt != nil {
		if decrypted, ok := decrypt(row.encryptedValue, metaVersion); ok {
			if decoded, ok := chromiumDecodeCookieValue(decrypted); ok {
				value = decoded
			}
		}
	}
	if value == "" {
		return Cookie{}, false
	}

	var expires *time.Time
	if row.expiresUTC != 0 {
		if t, ok := chromiumExpiresUTCToTime(row.expiresUTC); ok {
			expires = &t
		}
	}

	domain := strings.TrimPrefix(row.hostKey, ".")
	sameSite := chromiumSameSiteFromInt(row.sameSite)
	if row.path == "" {
		row.path = "/"
	}

	return Cookie{
		Name:     row.name,
		Value:    value,
		Domain:   domain,
		Path:     row.path,
		Secure:   row.isSecure,
		HTTPOnly: row.isHTTPOnly,
		SameSite: sameSite,
		Expires:  expires,
		Source: Source{
			Browser:    vendor.browser,
			Profile:    st.profile,
			StorePath:  st.cookiesDB,
			IsFallback: st.isFallback,
		},
	}, true
}

func chromiumSameSiteFromInt(v int64) SameSite {
	switch v {
	case 2:
		return SameSiteStrict
	case 1:
		return SameSiteLax
	case 0:
		return SameSiteNone
	default:
		return ""
	}
}

func chromiumExpiresUTCToTime(expiresUTC int64) (time.Time, bool) {
	// Chromium stores times as microseconds since 1601-01-01 UTC.
	const unixEpochDiffMicros = int64(11644473600000000)
	unixMicros := expiresUTC - unixEpochDiffMicros
	if unixMicros <= 0 {
		return time.Time{}, false
	}
	return time.Unix(0, unixMicros*1000).UTC(), true
}

func originsToHosts(origins []requestOrigin) []string {
	if len(origins) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(origins))
	out := make([]string, 0, len(origins))
	for _, o := range origins {
		if o.host == "" {
			continue
		}
		if _, ok := seen[o.host]; ok {
			continue
		}
		seen[o.host] = struct{}{}
		out = append(out, o.host)
	}
	return out
}

func chromiumResolveStores(b Browser, profileOverride string) ([]chromiumStore, []string) {
	if profileOverride != "" {
		st, warnings := chromiumResolveStoreFromOverride(b, profileOverride)
		if len(st) > 0 {
			return st, warnings
		}
		return nil, warnings
	}

	roots := chromiumUserDataDirs(b)
	var out []chromiumStore
	var warnings []string
	for _, root := range roots {
		st, w := chromiumResolveStoresFromUserDataDir(b, root)
		warnings = append(warnings, w...)
		out = append(out, st...)
	}
	return out, warnings
}

func chromiumResolveStoresFromUserDataDir(b Browser, userDataDir string) ([]chromiumStore, []string) {
	localStatePath := filepath.Join(userDataDir, "Local State")
	localStateBytes, err := os.ReadFile(localStatePath)
	if err != nil {
		return nil, nil
	}

	var localState struct {
		Profile struct {
			InfoCache map[string]struct {
				IsUsingDefaultName bool `json:"is_using_default_name"`
				Name               string
			} `json:"info_cache"`
		} `json:"profile"`
	}
	if err := json.Unmarshal(localStateBytes, &localState); err != nil {
		// Fallback: still probe Default.
		return chromiumProbeDefaultStores(b, userDataDir), []string{fmt.Sprintf("sweetcookie: failed to parse Local State (%s): %v", userDataDir, err)}
	}

	var out []chromiumStore
	for profDir, prof := range localState.Profile.InfoCache {
		out = append(out, chromiumStoresForProfileDir(b, userDataDir, profDir, prof.Name, prof.IsUsingDefaultName)...)
	}
	return out, nil
}

func chromiumProbeDefaultStores(b Browser, userDataDir string) []chromiumStore {
	return chromiumStoresForProfileDir(b, userDataDir, "Default", "Default", true)
}

func chromiumStoresForProfileDir(b Browser, userDataDir string, profDir string, profName string, isDefault bool) []chromiumStore {
	_ = b
	var out []chromiumStore
	candidates := []string{
		filepath.Join(userDataDir, profDir, "Network", "Cookies"),
		filepath.Join(userDataDir, profDir, "Cookies"),
	}
	for _, p := range candidates {
		if fileExists(p) {
			out = append(out, chromiumStore{
				cookiesDB: p,
				userData:  userDataDir,
				profile:   profName,
				isDefault: isDefault,
			})
		}
	}
	return out
}

func chromiumResolveStoreFromOverride(b Browser, override string) ([]chromiumStore, []string) {
	override = strings.TrimSpace(override)
	if override == "" {
		return nil, nil
	}

	// 1) Explicit file/directory.
	if fi, err := os.Stat(override); err == nil {
		if fi.IsDir() {
			return chromiumResolveFromProfileDir(b, override), nil
		}
		return chromiumResolveFromCookiesDBPath(b, override)
	}

	// 2) Treat as profile name across known roots.
	var out []chromiumStore
	roots := chromiumUserDataDirs(b)
	for _, root := range roots {
		out = append(out, chromiumStoresForProfileDir(b, root, override, override, false)...)
	}
	if len(out) == 0 {
		return nil, []string{fmt.Sprintf("sweetcookie: %s profile %q not found", b, override)}
	}
	return out, nil
}

func chromiumResolveFromProfileDir(b Browser, profileDir string) []chromiumStore {
	_ = b
	// Profile dir contains `Cookies` or `Network/Cookies`.
	candidates := []string{
		filepath.Join(profileDir, "Network", "Cookies"),
		filepath.Join(profileDir, "Cookies"),
	}
	for _, p := range candidates {
		if fileExists(p) {
			userData := filepath.Dir(profileDir)
			return []chromiumStore{{
				cookiesDB: p,
				userData:  userData,
				profile:   filepath.Base(profileDir),
				isDefault: false,
			}}
		}
	}
	return nil
}

func chromiumResolveFromCookiesDBPath(b Browser, cookiesDBPath string) ([]chromiumStore, []string) {
	if !fileExists(cookiesDBPath) {
		return nil, []string{fmt.Sprintf("sweetcookie: %s cookies DB not found at %q", b, cookiesDBPath)}
	}

	dir := filepath.Dir(cookiesDBPath)
	if filepath.Base(dir) == "Network" {
		dir = filepath.Dir(dir)
	}
	userDataDir := filepath.Dir(dir)
	return []chromiumStore{{
		cookiesDB: cookiesDBPath,
		userData:  userDataDir,
		profile:   filepath.Base(dir),
	}}, nil
}

func fileExists(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && !fi.IsDir()
}
