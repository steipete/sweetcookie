package sweetcookie

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite" // SQLite driver (pure Go).
)

type chromiumCookieRow struct {
	hostKey        string
	name           string
	path           string
	value          string
	encryptedValue []byte
	expiresUTC     int64
	isSecure       bool
	isHTTPOnly     bool
	sameSite       int64
}

func chromiumOpenSnapshotReadOnly(ctx context.Context, dbPath string) (snapshotPath string, cleanup func(), warnings []string, err error) {
	_ = ctx
	dir, err := os.MkdirTemp("", "sweetcookie-chromium-")
	if err != nil {
		return "", nil, nil, err
	}
	cleanup = func() { _ = os.RemoveAll(dir) }

	target := filepath.Join(dir, "Cookies")
	if err := copyFile(dbPath, target); err != nil {
		warnings = append(warnings, fmt.Sprintf("sweetcookie: failed to copy cookies DB: %v", err))
		cleanup()
		return "", nil, warnings, err
	}

	// If WAL mode is enabled, recent writes may live in sidecars.
	_ = copyFileIfExists(dbPath+"-wal", target+"-wal")
	_ = copyFileIfExists(dbPath+"-shm", target+"-shm")

	return target, cleanup, warnings, nil
}

func chromiumOpenDB(ctx context.Context, snapshotPath string) (*sql.DB, error) {
	dsn := "file:" + filepath.ToSlash(snapshotPath) + "?mode=ro"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}

func chromiumMetaVersion(ctx context.Context, db *sql.DB) int64 {
	if db == nil {
		return 0
	}
	var value string
	err := db.QueryRowContext(ctx, `SELECT value FROM meta WHERE key = 'version'`).Scan(&value)
	if err != nil {
		return 0
	}
	v, err := parseInt64(value)
	if err != nil {
		return 0
	}
	return v
}

func chromiumReadCookieRows(ctx context.Context, db *sql.DB, hosts []string) ([]chromiumCookieRow, error) {
	if db == nil {
		return nil, errors.New("nil db")
	}

	where, args := chromiumHostWhereClause(hosts)
	query := strings.Join([]string{
		`SELECT host_key, name, path, value, encrypted_value, expires_utc, is_secure, is_httponly, samesite`,
		`FROM cookies`,
		`WHERE (` + where + `)`,
		`ORDER BY expires_utc DESC`,
	}, " ")

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []chromiumCookieRow
	for rows.Next() {
		var r chromiumCookieRow
		var encrypted []byte
		var expires sql.NullInt64
		var secure sql.NullInt64
		var httpOnly sql.NullInt64
		var sameSite sql.NullInt64

		if err := rows.Scan(&r.hostKey, &r.name, &r.path, &r.value, &encrypted, &expires, &secure, &httpOnly, &sameSite); err != nil {
			return nil, err
		}

		r.encryptedValue = encrypted
		if expires.Valid {
			r.expiresUTC = expires.Int64
		}
		r.isSecure = secure.Valid && secure.Int64 == 1
		r.isHTTPOnly = httpOnly.Valid && httpOnly.Int64 == 1
		if sameSite.Valid {
			r.sameSite = sameSite.Int64
		}

		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func chromiumHostWhereClause(hosts []string) (string, []any) {
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
			clauses = append(clauses, "host_key = ?", "host_key = ?", "host_key LIKE ?")
			args = append(args, candidate, "."+candidate, "%."+candidate)
		}
	}
	if len(clauses) == 0 {
		return "1=0", nil
	}
	return strings.Join(clauses, " OR "), args
}

func expandHostCandidates(host string) []string {
	parts := strings.Split(host, ".")
	cleaned := make([]string, 0, len(parts))
	for _, p := range parts {
		if p == "" {
			continue
		}
		cleaned = append(cleaned, p)
	}
	if len(cleaned) <= 1 {
		return []string{host}
	}

	seen := make(map[string]struct{}, len(cleaned))
	var out []string
	add := func(h string) {
		if h == "" {
			return
		}
		if _, ok := seen[h]; ok {
			return
		}
		seen[h] = struct{}{}
		out = append(out, h)
	}

	add(host)
	for i := 1; i <= len(cleaned)-2; i++ {
		add(strings.Join(cleaned[i:], "."))
	}
	return out
}
