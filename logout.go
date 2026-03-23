package oidc_handlers

import "net/url"

func logoutURI(endSession, rawIDToken string) (string, error) {
	u, err := url.Parse(endSession)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("id_token_hint", rawIDToken)
	u.RawQuery = q.Encode()
	return u.String(), nil
}
