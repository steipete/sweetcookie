package sweetcookie

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"time"
)

func inlineAny(in InlineCookies) bool {
	return len(in.JSON) > 0 || in.Base64 != "" || in.File != ""
}

type inlinePayload struct {
	Cookies []inlineCookie `json:"cookies"`
}

type inlineCookie struct {
	Name     string      `json:"name"`
	Value    string      `json:"value"`
	Domain   string      `json:"domain"`
	Path     string      `json:"path"`
	Secure   bool        `json:"secure"`
	HTTPOnly bool        `json:"httpOnly"`
	SameSite string      `json:"sameSite"`
	Expires  interface{} `json:"expires"`
}

func readInlineCookies(in InlineCookies) ([]Cookie, []string, error) {
	raw, warnings, err := readInlineBytes(in)
	if err != nil {
		return nil, warnings, err
	}
	raw = bytesTrimSpace(raw)
	if len(raw) == 0 {
		return nil, warnings, errors.New("sweetcookie: inline cookies empty")
	}

	// Support both `Cookie[]` and `{ cookies: Cookie[] }`.
	var payload inlinePayload
	if err := json.Unmarshal(raw, &payload); err == nil && len(payload.Cookies) > 0 {
		return inlineToCookies(payload.Cookies), warnings, nil
	}

	var arr []inlineCookie
	if err := json.Unmarshal(raw, &arr); err != nil {
		return nil, warnings, err
	}
	return inlineToCookies(arr), warnings, nil
}

func readInlineBytes(in InlineCookies) ([]byte, []string, error) {
	switch {
	case len(in.JSON) > 0:
		return in.JSON, nil, nil
	case in.Base64 != "":
		b, err := base64.StdEncoding.DecodeString(in.Base64)
		if err != nil {
			return nil, nil, err
		}
		return b, nil, nil
	case in.File != "":
		b, err := os.ReadFile(in.File)
		if err != nil {
			return nil, nil, err
		}
		return b, nil, nil
	default:
		return nil, nil, errors.New("sweetcookie: no inline cookie source provided")
	}
}

func inlineToCookies(in []inlineCookie) []Cookie {
	if len(in) == 0 {
		return nil
	}
	out := make([]Cookie, 0, len(in))
	for _, c := range in {
		cc := Cookie{
			Name:     c.Name,
			Value:    c.Value,
			Domain:   c.Domain,
			Path:     c.Path,
			Secure:   c.Secure,
			HTTPOnly: c.HTTPOnly,
			SameSite: normalizeSameSite(c.SameSite),
			Source: Source{
				Browser: BrowserInline,
			},
		}
		if expires := parseInlineExpires(c.Expires); expires != nil {
			cc.Expires = expires
		}
		out = append(out, cc)
	}
	return out
}

func parseInlineExpires(v interface{}) *time.Time {
	switch vv := v.(type) {
	case nil:
		return nil
	case float64:
		// JSON numbers come through as float64.
		sec := int64(vv)
		if sec <= 0 {
			return nil
		}
		t := time.Unix(sec, 0).UTC()
		return &t
	case string:
		if vv == "" {
			return nil
		}
		if t, err := time.Parse(time.RFC3339, vv); err == nil {
			tt := t.UTC()
			return &tt
		}
		return nil
	default:
		return nil
	}
}

func normalizeSameSite(v string) SameSite {
	switch v {
	case "Strict", "strict":
		return SameSiteStrict
	case "Lax", "lax":
		return SameSiteLax
	case "None", "none", "NoRestriction", "no_restriction":
		return SameSiteNone
	default:
		return ""
	}
}
