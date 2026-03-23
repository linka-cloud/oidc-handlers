package oidc_handlers

import oidc "github.com/zitadel/oidc/v3/pkg/oidc"

type Token struct {
	oidc.IDTokenClaims
	Name     string   `json:"name"`
	Email    string   `json:"email"`
	Verified bool     `json:"email_verified"`
	Groups   []string `json:"groups"`
}

func (t *Token) claims() Claims {
	if t == nil {
		return Claims{}
	}
	return Claims{
		ID:       t.GetSubject(),
		Name:     t.Name,
		Email:    t.Email,
		Verified: t.Verified,
		Groups:   t.Groups,
	}
}
