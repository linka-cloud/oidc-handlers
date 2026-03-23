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
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/sirupsen/logrus"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"golang.org/x/oauth2"
)

var (
	_ DeviceHandler = (*deviceHandler)(nil)
)

type DeviceHandler interface {
	Exchange(ctx context.Context, opts ...oauth2.AuthCodeOption) (DeviceVerifier, error)
	Refresh(ctx context.Context, token *Token, refresh string) (tk *Token, rawIDToken, refreshToken string, err error)
	Logout(ctx context.Context, tk *Token, rawIDToken, refreshToken string) error
}

type deviceHandler struct {
	rp  rp.RelyingParty
	log logrus.FieldLogger
}

func (d *deviceHandler) Exchange(ctx context.Context, opts ...oauth2.AuthCodeOption) (DeviceVerifier, error) {
	oauth := d.rp.OAuthConfig()
	opts = append(opts, oauth2.SetAuthURLParam("client_secret", oauth.ClientSecret))
	a, err := oauth.DeviceAuth(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return &deviceVerifier{d: d, a: a}, nil
}

func (d *deviceHandler) Refresh(ctx context.Context, token *Token, refresh string) (tk *Token, rawIDToken, refreshToken string, err error) {
	return d.refresh(ctx, token, refresh, false)
}

func (d *deviceHandler) refresh(ctx context.Context, token *Token, refresh string, allowMissingIDToken bool) (tk *Token, rawIDToken, refreshToken string, err error) {
	d.log.Info("refreshing token")
	tks, err := rp.RefreshTokens[*Token](ctx, d.rp, refresh, "", "")
	if err != nil {
		d.log.WithError(err).Error("refresh token")
		return nil, "", "", err
	}

	refreshToken = pickRefresh(tks.RefreshToken, refresh)

	rawIDToken = tks.IDToken
	if rawIDToken == "" {
		if !allowMissingIDToken {
			d.log.Error("id_token not found")
			return nil, "", "", errors.New("id_token not found")
		}
		d.log.Warn("refresh response missing id_token")
		return token, "", refreshToken, nil
	}

	tk = tks.IDTokenClaims
	if tk == nil {
		d.log.Error("id_token claims not found")
		return nil, "", "", errors.New("id_token claims not found")
	}

	d.log.Info("token refreshed")
	return tk, rawIDToken, refreshToken, nil
}

func (d *deviceHandler) Logout(ctx context.Context, tk *Token, rawIDToken, refreshToken string) error {
	if d.rp.GetEndSessionEndpoint() == "" {
		return nil
	}
	_, refreshedIDToken, _, err := d.refresh(ctx, tk, refreshToken, true)
	if err != nil {
		return fmt.Errorf("refresh token: %w", err)
	}
	if refreshedIDToken != "" {
		rawIDToken = refreshedIDToken
	}
	if rawIDToken == "" {
		return errors.New("id_token not found")
	}
	endSession, err := logoutURI(d.rp.GetEndSessionEndpoint(), rawIDToken)
	if err != nil {
		return fmt.Errorf("end session url: %v", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endSession, nil)
	if err != nil {
		return err
	}
	res, err := d.rp.HttpClient().Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusOK {
		return nil
	}
	b, _ := io.ReadAll(res.Body)
	return fmt.Errorf("end session: %s", string(b))
}

type DeviceVerifier interface {
	URI() string
	Verify(ctx context.Context) (tk *Token, rawIDToken, refreshToken string, err error)
}

type deviceVerifier struct {
	d *deviceHandler
	a *oauth2.DeviceAuthResponse
}

func (v *deviceVerifier) URI() string {
	if v.a.VerificationURIComplete != "" {
		return v.a.VerificationURIComplete
	}
	return v.a.VerificationURI
}

func (v *deviceVerifier) Verify(ctx context.Context) (tk *Token, rawIDToken, refreshToken string, err error) {
	oauth2Token, err := v.d.rp.OAuthConfig().DeviceAccessToken(ctx, v.a)
	if err != nil {
		return nil, "", "", err
	}
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		return nil, "", "", errors.New("id_token not found")
	}
	if rawIDToken == "" {
		return nil, "", "", errors.New("id_token not found")
	}
	tk, err = rp.VerifyTokens[*Token](ctx, oauth2Token.AccessToken, rawIDToken, v.d.rp.IDTokenVerifier())
	if err != nil {
		return nil, "", "", err
	}
	return tk, rawIDToken, oauth2Token.RefreshToken, nil
}
