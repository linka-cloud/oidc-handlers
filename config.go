package oidc_handlers

import (
	"github.com/sirupsen/logrus"
)

type Config struct {
	IssuerURL     string
	ClientID      string
	ClientSecret  string
	OauthCallback string
	CookieConfig  CookieConfig
	Scopes        []string
	Logger        logrus.FieldLogger
}

type CookieConfig struct {
	IDTokenName      string
	RefreshTokenName string
	AuthStateName    string
	RedirectName     string
	Domain           string
	Secure           bool
}
