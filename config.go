package oidc_handlers

import (
	"context"
	"io"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
)

var now = time.Now

const (
	DefaultIDTokenName      = "id_token"
	DefaultRefreshTokenName = "refresh_token"
	DefaultAuthStateName    = "auth_state"
	DefaultRedirectName     = "redirect"
)

type CookieConfig struct {
	IDTokenName      string
	RefreshTokenName string
	AuthStateName    string
	RedirectName     string
	Domain           string
	Secure           bool
}

func (c *CookieConfig) Defaults() {
	if c.RefreshTokenName == "" {
		c.RefreshTokenName = DefaultRefreshTokenName
	}
	if c.IDTokenName == "" {
		c.IDTokenName = DefaultIDTokenName
	}
	if c.AuthStateName == "" {
		c.AuthStateName = DefaultAuthStateName
	}
	if c.RedirectName == "" {
		c.RedirectName = DefaultRedirectName
	}
}

type Config struct {
	IssuerURL     string
	ClientID      string
	ClientSecret  string
	OauthCallback string
	CookieConfig  CookieConfig
	Scopes        []string
	Logger        logrus.FieldLogger
}

func (c *Config) Defaults() {
	c.CookieConfig.Defaults()
	if len(c.Scopes) == 0 {
		c.Scopes = []string{oidc.ScopeOpenID, oidc.ScopeOfflineAccess, "profile", "email", "groups"}
	}
	if c.Logger == nil {
		log := logrus.New()
		log.SetOutput(io.Discard)
		c.Logger = log
	}
}

func (c *Config) apply(ctx context.Context) (oauth2.Config, *oidc.IDTokenVerifier, error) {
	c.Defaults()
	provider, err := oidc.NewProvider(ctx, c.IssuerURL)
	if err != nil {
		return oauth2.Config{}, nil, err
	}
	// Configure an OpenID Connect aware OAuth2 client.
	oauth2Config := oauth2.Config{
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
		RedirectURL:  c.OauthCallback,
		Endpoint:     provider.Endpoint(),
		Scopes:       c.Scopes,
	}
	verifier := provider.Verifier(&oidc.Config{ClientID: c.ClientID, SkipExpiryCheck: true, Now: now})
	return oauth2Config, verifier, nil
}

// WebHandler creates a web auth flow handler from config
func (c *Config) WebHandler(ctx context.Context) (WebHandler, error) {
	oauth2Config, verifier, err := c.apply(ctx)
	if err != nil {
		return nil, err
	}
	return &webHandler{
		cookieConfig: c.CookieConfig,
		oauth:        oauth2Config,
		verifier:     verifier,
		now:          now,
		log:          c.Logger.WithField("oidc", "web"),
	}, nil
}

func (c *Config) DeviceHandler(ctx context.Context) (DeviceHandler, error) {
	oauth2Config, verifier, err := c.apply(ctx)
	if err != nil {
		return nil, err
	}
	return &device{
		oauth:        oauth2Config,
		verifier:     verifier,
		now:          now,
		log:          c.Logger.WithField("oidc", "device"),
	}, nil
}
