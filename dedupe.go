package sweetcookie

func dedupeCookies(cookies []Cookie) []Cookie {
	if len(cookies) == 0 {
		return nil
	}

	merged := make(map[string]Cookie, len(cookies))
	out := make([]Cookie, 0, len(cookies))
	for _, c := range cookies {
		key := c.Name + "\x00" + c.Domain + "\x00" + c.Path
		if _, ok := merged[key]; ok {
			continue
		}
		merged[key] = c
		out = append(out, c)
	}
	return out
}
