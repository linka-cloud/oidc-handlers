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
	"io"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/securecookie"
	"github.com/sirupsen/logrus"
	"go.linka.cloud/go-oidc/v3/oidc"
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
	Logger        logrus.FieldLogger
	Opts          func(ctx context.Context) []oauth2.AuthCodeOption
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

// WebHandler creates a web auth flow handler from config
func (c *Config) WebHandler(ctx context.Context) (WebHandler, error) {
	oauth2Config, verifier, endSession, err := c.apply(ctx)
	if err != nil {
		return nil, err
	}
	return &webHandler{
		cookieConfig: c.CookieConfig,
		oauth:        oauth2Config,
		verifier:     verifier,
		now:          now,
		log:          c.Logger.WithField("oidc", "web"),
		opts:         c.Opts,
		endSession:   endSession,
	}, nil
}

func (c *Config) LazyWebHandler(ctx context.Context) (WebHandler, error) {
	return &lazyWebHandler{ctx: ctx, log: c.Logger.WithField("service", "oidcHandlers"), config: c}, nil
}

func (c *Config) DeviceHandler(ctx context.Context) (DeviceHandler, error) {
	oauth2Config, verifier, endSession, err := c.apply(ctx)
	if err != nil {
		return nil, err
	}
	return &deviceHandler{
		oauth:      oauth2Config,
		verifier:   verifier,
		log:        c.Logger.WithField("oidc", "device"),
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
		log:      c.Logger.WithField("oidc", "grpc"),
	}, nil
}

func (c *Config) LazyGRPCHandler(ctx context.Context) (GRPCHandler, error) {
	return &lazyGRPCHandler{
		ctx:    ctx,
		config: c,
	}, nil
}
