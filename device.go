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
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
)

var (
	_ DeviceHandler = (*device)(nil)
)

type DeviceHandler interface {
	Exchange(ctx context.Context) (DeviceVerifier, error)
	Refresh(ctx context.Context, token *oidc.IDToken, refresh string) (tk *oidc.IDToken, refreshToken string, err error)
}

type device struct {
	oauth oauth2.Config

	verifier *oidc.IDTokenVerifier
	log      logrus.FieldLogger

	now func() time.Time
	mu  sync.RWMutex
}

func (d *device) Exchange(ctx context.Context) (DeviceVerifier, error) {
	a, err := d.oauth.AuthDevice(ctx, oauth2.SetAuthURLParam("client_secret", d.oauth.ClientSecret))
	if err != nil {
		return nil, err
	}
	return &deviceVerifier{d: d, a: a}, nil
}

func (d *device) Refresh(ctx context.Context, token *oidc.IDToken, refresh string) (tk *oidc.IDToken, refreshToken string, err error) {
	d.log.Info("refreshing token")
	tks := d.oauth.TokenSource(ctx, &oauth2.Token{RefreshToken: refresh, Expiry: token.Expiry})
	oauth2Token, err := tks.Token()
	if err != nil {
		d.log.WithError(err).Error("refresh token")
		return nil, "", err
	}
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		d.log.Error("id_token not found")
		return nil, "", errors.New("id_token not found")
	}
	tk, err = d.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		d.log.WithError(err).Error("verify token")
		return nil, "", fmt.Errorf("verify token: %w", err)
	}
	d.log.Info("token refreshed")
	return tk, oauth2Token.Extra("id_token").(string), nil
}

type DeviceVerifier interface {
	URI() string
	Verify(ctx context.Context) (tk *oidc.IDToken, refreshToken string, err error)
}

type deviceVerifier struct {
	d *device
	a *oauth2.DeviceAuth
}

func (v *deviceVerifier) URI() string {
	if v.a.VerificationURIComplete != "" {
		return v.a.VerificationURIComplete
	}
	return v.a.VerificationURI
}

func (v *deviceVerifier) Verify(ctx context.Context) (tk *oidc.IDToken, refreshToken string, err error) {
	oauth2Token, err := v.d.oauth.Poll(ctx, v.a)
	if err != nil {
		return nil, "", err
	}
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		return nil, "", errors.New("id_token not found")
	}

	tk, err = v.d.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, "", err
	}
	return tk, oauth2Token.RefreshToken, nil
}
