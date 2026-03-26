/*
 * Copyright 2021 Linka Cloud  All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package oidc_handlers

import (
	"context"
	"crypto/sha256"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/securecookie"
	"go.linka.cloud/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

var now = time.Now

const (
	DefaultIDTokenName      = "id_token"
	DefaultRefreshTokenName = "refresh_token"
	DefaultAuthStateName    = "auth_state"
	DefaultRedirectName     = "redirect"
	DefaultLoginEndpoint    = "/auth"
	DefaultCallbackEndpoint = "/auth/callback"
	DefaultLogoutEndpoint   = "/logout"
)

// Endpoints configures the exact application routes managed by WebMiddleware.
//
// Login, Callback, and Logout are matched as exact paths.
// PostLogoutRedirectURI is forwarded to the provider when RP-initiated logout is available,
// and is also used as a local fallback after cookies are cleared.
type Endpoints struct {
	Login                 string
	Callback              string
	Logout                string
	PostLogoutRedirectURI string
}

func (c *Endpoints) Defaults() {
	if c.Login == "" {
		c.Login = DefaultLoginEndpoint
	}
	if c.Callback == "" {
		c.Callback = DefaultCallbackEndpoint
	}
	if c.Logout == "" {
		c.Logout = DefaultLogoutEndpoint
	}
}

type CookieConfig struct {
	IDTokenName      string
	RefreshTokenName string
	AuthStateName    string
	RedirectName     string
	Domain           string
	Secure           bool
	Key              string

	key []byte
	sec *securecookie.SecureCookie
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
	if c.Key != "" {
		k := sha256.Sum256([]byte(c.Key))
		c.key = k[:]
		c.sec = securecookie.New(c.key, c.key)
	}
}

type Config struct {
	IssuerURL     string
	ClientID      string
	ClientSecret  string
	OauthCallback string
	CookieConfig  CookieConfig
	Scopes        []string
	Opts          func(ctx context.Context) []oauth2.AuthCodeOption
}

func (c *Config) Defaults() {
	c.CookieConfig.Defaults()
	if len(c.Scopes) == 0 {
		c.Scopes = []string{oidc.ScopeOpenID, oidc.ScopeOfflineAccess, "profile", "email", "groups"}
	}
	if c.Opts == nil {
		c.Opts = func(ctx context.Context) []oauth2.AuthCodeOption {
			return []oauth2.AuthCodeOption{oidc.Nonce(uuid.New().String())}
		}
	}
}

func (c *Config) apply(ctx context.Context) (oauth2.Config, *oidc.IDTokenVerifier, string, error) {
	c.Defaults()
	provider, err := oidc.NewProvider(ctx, c.IssuerURL)
	if err != nil {
		return oauth2.Config{}, nil, "", err
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
	return oauth2Config, verifier, provider.EndSessionURL(), nil
}

func (c *Config) webHandler(ctx context.Context) (*webHandler, error) {
	oauth2Config, verifier, endSession, err := c.apply(ctx)
	if err != nil {
		return nil, err
	}
	return &webHandler{
		cookieConfig: c.CookieConfig,
		oauth:        oauth2Config,
		verifier:     verifier,
		now:          now,
		opts:         c.Opts,
		endSession:   endSession,
	}, nil
}

// WebHandler creates a web auth flow handler from config
func (c *Config) WebHandler(ctx context.Context) (WebHandler, error) {
	return c.webHandler(ctx)
}

// WebMiddleware returns a middleware that manages the configured OIDC endpoints.
func (c *Config) WebMiddleware(ctx context.Context, endpoints Endpoints) (func(http.Handler) http.Handler, error) {
	h, err := c.webHandler(ctx)
	if err != nil {
		return nil, err
	}
	return h.webMiddleware(endpoints), nil
}

func (c *Config) LazyWebHandler(ctx context.Context) (WebHandler, error) {
	return &lazyWebHandler{ctx: ctx, config: c}, nil
}

// LazyWebMiddleware is the lazy version of WebMiddleware.
func (c *Config) LazyWebMiddleware(ctx context.Context, endpoints Endpoints) (func(http.Handler) http.Handler, error) {
	return (&lazyWebHandler{ctx: ctx, config: c}).webMiddleware(endpoints), nil
}

func (c *Config) DeviceHandler(ctx context.Context) (DeviceHandler, error) {
	oauth2Config, verifier, endSession, err := c.apply(ctx)
	if err != nil {
		return nil, err
	}
	return &deviceHandler{
		oauth:      oauth2Config,
		verifier:   verifier,
		endSession: endSession,
	}, nil
}

func (c *Config) GRPC(ctx context.Context) (GRPCHandler, error) {
	oauth2Config, verifier, _, err := c.apply(ctx)
	if err != nil {
		return nil, err
	}
	return &grpcHandler{
		oauth:    oauth2Config,
		verifier: verifier,
	}, nil
}

func (c *Config) LazyGRPCHandler(ctx context.Context) (GRPCHandler, error) {
	return &lazyGRPCHandler{
		ctx:    ctx,
		config: c,
	}, nil
}
