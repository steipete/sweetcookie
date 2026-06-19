package sweetcookie

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/go-ini/ini"
)

func readFirefoxCookies(ctx context.Context, b Browser, profileOverride string, origins []requestOrigin, _ Options) ([]Cookie, []string, error) {
	dbs, warnings := firefoxResolveCookieDBs(b, profileOverride)
	if len(dbs) == 0 {
		return nil, append(warnings, fmt.Sprintf("sweetcookie: %s cookie store not found", b)), nil
	}

	hosts := originsToHosts(origins)
	var out []Cookie
	for _, dbPath := range dbs {
		snap, cleanup, _, err := chromiumOpenSnapshotReadOnly(ctx, dbPath.path)
		if err != nil {
			continue
		}
		func() {
			defer cleanup()

			db, err := chromiumOpenDB(ctx, snap)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("sweetcookie: failed to open %s cookies DB: %v", b, err))
				return
			}
			defer func() { _ = db.Close() }()

			rows, err := firefoxReadRows(ctx, db, hosts)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("sweetcookie: failed to read %s cookies: %v", b, err))
				return
			}
			for _, r := range rows {
				c, ok := firefoxRowToCookie(dbPath, r)
				if !ok {
					continue
				}
				out = append(out, c)
			}
		}()
	}

	return out, warnings, nil
}

type firefoxDB struct {
	path       string
	profile    string
	browser    Browser
	containers map[int]string
}

func newFirefoxDB(b Browser, dbPath, profile string) firefoxDB {
	return firefoxDB{
		path:       dbPath,
		profile:    profile,
		browser:    b,
		containers: firefoxLoadContainers(filepath.Dir(dbPath)),
	}
}

func firefoxResolveCookieDBs(b Browser, override string) ([]firefoxDB, []string) {
	override = strings.TrimSpace(override)
	if override != "" {
		if fi, err := os.Stat(override); err == nil {
			if fi.IsDir() {
				dbPath := filepath.Join(override, "cookies.sqlite")
				if fileExists(dbPath) {
					return []firefoxDB{newFirefoxDB(b, dbPath, filepath.Base(override))}, nil
				}
				return nil, []string{fmt.Sprintf("sweetcookie: %s cookies.sqlite not found in %q", b, override)}
			}
			return []firefoxDB{newFirefoxDB(b, override, filepath.Base(filepath.Dir(override)))}, nil
		}
	}

	var out []firefoxDB
	for _, root := range firefoxRoots(b) {
		iniPath := filepath.Join(root, "profiles.ini")
		cfg, err := ini.Load(iniPath)
		if err != nil {
			continue
		}

		for _, secName := range cfg.SectionStrings() {
			if !strings.HasPrefix(secName, "Profile") {
				continue
			}
			sec := cfg.Section(secName)
			name := sec.Key("Name").String()
			pathStr := filepath.FromSlash(sec.Key("Path").String())
			if pathStr == "" {
				continue
			}
			if sec.Key("IsRelative").String() == "1" {
				pathStr = filepath.Join(root, pathStr)
			}
			dbPath := filepath.Join(pathStr, "cookies.sqlite")
			if !fileExists(dbPath) {
				continue
			}

			prof := name
			if prof == "" {
				prof = filepath.Base(pathStr)
			}
			if override != "" && prof != override && filepath.Base(pathStr) != override {
				continue
			}
			out = append(out, newFirefoxDB(b, dbPath, prof))
		}
	}

	if override != "" && len(out) == 0 {
		return nil, []string{fmt.Sprintf("sweetcookie: %s profile %q not found", b, override)}
	}
	return out, nil
}

// firefoxLoadContainers returns container names keyed by profile-local userContextId.
func firefoxLoadContainers(profileDir string) map[int]string {
	raw, err := os.ReadFile(filepath.Join(profileDir, "containers.json"))
	if err != nil {
		return nil
	}
	var doc struct {
		Identities []struct {
			UserContextID int    `json:"userContextId"`
			Name          string `json:"name"`
		} `json:"identities"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil
	}
	out := make(map[int]string, len(doc.Identities))
	for _, id := range doc.Identities {
		if id.UserContextID > 0 && id.Name != "" {
			out[id.UserContextID] = id.Name
		}
	}
	return out
}

// firefoxContainerFromOriginAttributes extracts a profile-local userContextId.
func firefoxContainerFromOriginAttributes(originAttributes string, names map[int]string) Container {
	trimmed := strings.TrimPrefix(originAttributes, "^")
	for _, part := range strings.Split(trimmed, "&") {
		value, ok := strings.CutPrefix(part, "userContextId=")
		if !ok {
			continue
		}
		id, err := strconv.Atoi(value)
		if err != nil || id <= 0 {
			return Container{}
		}
		return Container{ID: id, Name: names[id]}
	}
	return Container{}
}

type firefoxRow struct {
	host             string
	name             string
	value            string
	path             string
	expiry           int64
	isSecure         bool
	httpOnly         bool
	sameSite         int64
	originAttributes string
}

func firefoxReadRows(ctx context.Context, db *sql.DB, hosts []string) ([]firefoxRow, error) {
	where, args := firefoxHostWhereClause(hosts)
	//nolint:gosec // `where` is generated with placeholders; hosts are passed via args.
	query := `SELECT host, name, value, path, expiry, isSecure, isHttpOnly, sameSite, originAttributes FROM moz_cookies WHERE (` + where + `) ORDER BY expiry DESC`

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []firefoxRow
	for rows.Next() {
		var r firefoxRow
		var expiry sql.NullInt64
		var secure sql.NullInt64
		var httpOnly sql.NullInt64
		var sameSite sql.NullInt64
		var originAttributes sql.NullString

		if err := rows.Scan(&r.host, &r.name, &r.value, &r.path, &expiry, &secure, &httpOnly, &sameSite, &originAttributes); err != nil {
			return nil, err
		}
		if expiry.Valid {
			r.expiry = expiry.Int64
		}
		r.isSecure = secure.Valid && secure.Int64 == 1
		r.httpOnly = httpOnly.Valid && httpOnly.Int64 == 1
		if sameSite.Valid {
			r.sameSite = sameSite.Int64
		}
		if originAttributes.Valid {
			r.originAttributes = originAttributes.String
		}

		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func firefoxHostWhereClause(hosts []string) (string, []any) {
	if len(hosts) == 0 {
		return "1=1", nil
	}

	var clauses []string
	var args []any
	for _, host := range hosts {
		host = normalizeHost(host)
		if host == "" {
			continue
		}
		for _, candidate := range expandHostCandidates(host) {
			clauses = append(clauses, "host = ?", "host = ?", "host LIKE ?")
			args = append(args, candidate, "."+candidate, "%."+candidate)
		}
	}
	if len(clauses) == 0 {
		return "1=0", nil
	}
	return strings.Join(clauses, " OR "), args
}

func firefoxRowToCookie(db firefoxDB, r firefoxRow) (Cookie, bool) {
	if r.name == "" {
		return Cookie{}, false
	}
	if r.host == "" {
		return Cookie{}, false
	}
	if r.value == "" {
		return Cookie{}, false
	}
	if r.path == "" {
		r.path = "/"
	}

	var expires *time.Time
	if r.expiry > 0 {
		t := time.Unix(r.expiry, 0).UTC()
		expires = &t
	}

	return Cookie{
		Name:      r.name,
		Value:     r.value,
		Domain:    strings.TrimPrefix(r.host, "."),
		Path:      r.path,
		Secure:    r.isSecure,
		HTTPOnly:  r.httpOnly,
		SameSite:  chromiumSameSiteFromInt(r.sameSite),
		Container: firefoxContainerFromOriginAttributes(r.originAttributes, db.containers),
		Expires:   expires,
		Source: Source{
			Browser:   db.browser,
			Profile:   db.profile,
			StorePath: db.path,
		},
	}, true
}
