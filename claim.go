package oidc_handlers

type Claims struct {
	ID       string   `json:"sub"`
	Name     string   `json:"name"`
	Email    string   `json:"email"`
	Verified bool     `json:"email_verified"`
	Groups   []string `json:"groups"`
}
