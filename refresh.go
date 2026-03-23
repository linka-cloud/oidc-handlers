package oidc_handlers

func pickRefresh(next, current string) string {
	if next == "" {
		return current
	}
	return next
}
