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
	"go.linka.cloud/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

var (
	_ DeviceHandler = (*deviceHandler)(nil)
)

type DeviceHandler interface {
	Exchange(ctx context.Context, opts ...oauth2.AuthCodeOption) (DeviceVerifier, error)
	Refresh(ctx context.Context, token *oidc.IDToken, refresh string) (tk *oidc.IDToken, rawIDToken, refreshToken string, err error)
	Logout(ctx context.Context, tk *oidc.IDToken, rawIDToken, refreshToken string) error
}

type deviceHandler struct {
	oauth oauth2.Config

	verifier   *oidc.IDTokenVerifier
	log        logrus.FieldLogger
	endSession string
}

func (d *deviceHandler) Exchange(ctx context.Context, opts ...oauth2.AuthCodeOption) (DeviceVerifier, error) {
	opts = append(opts, oauth2.SetAuthURLParam("client_secret", d.oauth.ClientSecret))
	a, err := d.oauth.DeviceAuth(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return &deviceVerifier{d: d, a: a}, nil
}

func (d *deviceHandler) Refresh(ctx context.Context, token *oidc.IDToken, refresh string) (tk *oidc.IDToken, rawIDToken, refreshToken string, err error) {
	d.log.Info("refreshing token")
	tks := d.oauth.TokenSource(ctx, &oauth2.Token{RefreshToken: refresh, Expiry: token.Expiry})
	oauth2Token, err := tks.Token()
	if err != nil {
		d.log.WithError(err).Error("refresh token")
		return nil, "", "", err
	}
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		d.log.Error("id_token not found")
		return nil, "", "", errors.New("id_token not found")
	}
	tk, err = d.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		d.log.WithError(err).Error("verify token")
		return nil, "", "", fmt.Errorf("verify token: %w", err)
	}
	d.log.Info("token refreshed")
	return tk, rawIDToken, oauth2Token.RefreshToken, nil
}

func (d *deviceHandler) Logout(ctx context.Context, tk *oidc.IDToken, rawIDToken, refreshToken string) error {
	if d.endSession == "" {
		return nil
	}
	_, rawIDToken, _, err := d.Refresh(ctx, tk, refreshToken)
	if err != nil {
		return fmt.Errorf("refresh token: %w", err)
	}
	u, err := logoutURI(d.endSession, rawIDToken)
	if err != nil {
		return fmt.Errorf("end session url: %v", err)
	}
	res, err := http.Get(u)
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
	Verify(ctx context.Context) (tk *oidc.IDToken, rawIDToken, refreshToken string, err error)
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

func (v *deviceVerifier) Verify(ctx context.Context) (tk *oidc.IDToken, rawIDToken, refreshToken string, err error) {
	oauth2Token, err := v.d.oauth.DeviceAccessToken(ctx, v.a)
	if err != nil {
		return nil, "", "", err
	}
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		return nil, "", "", errors.New("id_token not found")
	}

	tk, err = v.d.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, "", "", err
	}
	return tk, rawIDToken, oauth2Token.RefreshToken, nil
}
