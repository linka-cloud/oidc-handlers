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
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	oidc "github.com/zitadel/oidc/v3/pkg/oidc"
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
			return []oauth2.AuthCodeOption{oauth2.SetAuthURLParam("nonce", uuid.New().String())}
		}
	}
}

func (c *Config) newRP(ctx context.Context) (rp.RelyingParty, error) {
	c.Defaults()
	r, err := rp.NewRelyingPartyOIDC(ctx, c.IssuerURL, c.ClientID, c.ClientSecret, c.OauthCallback, c.Scopes)
	if err != nil {
		return nil, err
	}
	return r, nil
}

// WebHandler creates a web auth flow handler from config
func (c *Config) WebHandler(ctx context.Context) (WebHandler, error) {
	rp, err := c.newRP(ctx)
	if err != nil {
		return nil, err
	}
	return &webHandler{
		cookieConfig: c.CookieConfig,
		rp:           rp,
		now:          now,
		log:          c.Logger.WithField("oidc", "web"),
		opts:         c.Opts,
	}, nil
}

func (c *Config) LazyWebHandler(ctx context.Context) (WebHandler, error) {
	c.Defaults()
	return &lazyWebHandler{ctx: ctx, log: c.Logger.WithField("service", "oidcHandlers"), config: c}, nil
}

func (c *Config) DeviceHandler(ctx context.Context) (DeviceHandler, error) {
	rp, err := c.newRP(ctx)
	if err != nil {
		return nil, err
	}
	return &deviceHandler{
		rp:  rp,
		log: c.Logger.WithField("oidc", "device"),
	}, nil
}

func (c *Config) GRPC(ctx context.Context) (GRPCHandler, error) {
	rp, err := c.newRP(ctx)
	if err != nil {
		return nil, err
	}
	return &grpcHandler{
		rp:  rp,
		log: c.Logger.WithField("oidc", "grpc"),
	}, nil
}

func (c *Config) LazyGRPCHandler(ctx context.Context) (GRPCHandler, error) {
	c.Defaults()
	return &lazyGRPCHandler{
		ctx:    ctx,
		config: c,
	}, nil
}
