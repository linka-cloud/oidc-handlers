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
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
)

var (
	_ WebHandler = (*webHandler)(nil)
)

// Deprecated: use WebHandler instead
type Handler = WebHandler

// WebHandler is the oidc handler for standard web auth flow
type WebHandler interface {
	RedirectHandler(w http.ResponseWriter, r *http.Request)
	CallbackHandler(w http.ResponseWriter, r *http.Request)
	Callback(w http.ResponseWriter, r *http.Request) error
	Refresh(w http.ResponseWriter, r *http.Request) (idToken string, err error)
	SetRedirectCookie(w http.ResponseWriter, path string)
	CleanCookies(w http.ResponseWriter)
}

// Deprecated: use Config.WebHandler instead
func New(ctx context.Context, config Config) (Handler, error) {
	oauth2Config, verifier, err := config.apply(ctx)
	if err != nil {
		return nil, err
	}
	h := &webHandler{
		cookieConfig: config.CookieConfig,
		oauth:        oauth2Config,
		verifier:     verifier,
		now:          now,
		log:          config.Logger,
	}
	return h, nil
}

type webHandler struct {
	oauth        oauth2.Config
	cookieConfig CookieConfig

	verifier *oidc.IDTokenVerifier
	log      logrus.FieldLogger

	now func() time.Time
	mu  sync.RWMutex
}

func (h *webHandler) SetRedirectCookie(w http.ResponseWriter, path string) {
	http.SetCookie(w, h.cookie(h.cookieConfig.RedirectName, path))
}

func (h *webHandler) RedirectHandler(w http.ResponseWriter, r *http.Request) {
	log := h.log.WithField("path", r.URL.Path).WithField("method", r.Method)
	log.Info("redirect")
	h.ensureCookieDomain(r)
	state := newState()
	http.SetCookie(w, h.cookie(h.cookieConfig.AuthStateName, state))
	http.Redirect(w, r, h.oauth.AuthCodeURL(state), http.StatusFound)
}

func (h *webHandler) Callback(w http.ResponseWriter, r *http.Request) error {
	log := h.log.WithField("path", r.URL.Path).WithField("method", r.Method)
	log.Info("callback")
	stateCookie, err := r.Cookie(h.cookieConfig.AuthStateName)
	if err != nil {
		h.CleanCookies(w)
		return fmt.Errorf("state cookie: %w", err)
	}
	if r.URL.Query().Get("state") != stateCookie.Value {
		return errors.New("invalid state cookie")
	}
	oauth2Token, err := h.oauth.Exchange(r.Context(), r.URL.Query().Get("code"))
	if err != nil {
		h.CleanCookies(w)
		return fmt.Errorf("no token: %w", err)
	}
	if _, err := h.handleOauthToken(r.Context(), w, oauth2Token); err != nil {
		h.CleanCookies(w)
		return fmt.Errorf("invalid token: %w", err)
	}
	path := "/"
	if c, err := r.Cookie(h.cookieConfig.RedirectName); err == nil && c.Value != "" {
		path = c.Value
	}
	h.deleteCookie(w, h.cookieConfig.AuthStateName)
	h.deleteCookie(w, h.cookieConfig.RedirectName)
	http.Redirect(w, r, path, http.StatusSeeOther)
	return nil
}

func (h *webHandler) CallbackHandler(w http.ResponseWriter, r *http.Request) {
	if err := h.Callback(w, r); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
}

func (h *webHandler) Refresh(w http.ResponseWriter, r *http.Request) (string, error) {
	log := h.log.WithField("path", r.URL.Path).WithField("method", r.Method)
	log.Info("refresh")
	h.ensureCookieDomain(r)
	idCookie, err := r.Cookie(h.cookieConfig.IDTokenName)
	if err != nil {
		h.CleanCookies(w)
		return "", fmt.Errorf("oidc cookie: %w", err)
	}
	idToken, err := h.verifier.Verify(r.Context(), idCookie.Value)
	if err != nil {
		log.WithError(err).Error("verify token")
		h.CleanCookies(w)
		return "", err
	}
	log = log.WithField("hash", idToken.AccessTokenHash)

	if !idToken.Expiry.Before(h.now().Add(idToken.Expiry.Sub(idToken.IssuedAt) / 2)) {
		log.Infof("skipping refresh (expiry: %v)", idToken.Expiry)
		*r = *r.WithContext(oidcContext(r.Context(), idToken))
		return "", nil
	}
	refreshCookie, err := r.Cookie(h.cookieConfig.RefreshTokenName)
	if err != nil {
		h.CleanCookies(w)
		log.WithError(err).Error("refresh cookie")
		return "", fmt.Errorf("refresh cookie: %w", err)
	}
	tk := h.oauth.TokenSource(r.Context(), &oauth2.Token{RefreshToken: refreshCookie.Value, Expiry: idToken.Expiry})
	oauth2Token, err := tk.Token()
	if err != nil {
		log.WithError(err).Error("refresh token")
		return "", err
	}
	idToken, err = h.handleOauthToken(r.Context(), w, oauth2Token)
	if err != nil {
		log.WithError(err).Error("handle token")
		return "", err
	}
	log.Info("token refreshed")
	*r = *r.WithContext(oidcContext(r.Context(), idToken))
	return oauth2Token.Extra("id_token").(string), nil
}

func (h *webHandler) handleOauthToken(ctx context.Context, w http.ResponseWriter, oauth2Token *oauth2.Token) (*oidc.IDToken, error) {
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		return nil, errors.New("id_token not found")
	}

	tk, err := h.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("verify token: %w", err)
	}
	http.SetCookie(w, h.cookie(h.cookieConfig.RefreshTokenName, oauth2Token.RefreshToken))
	http.SetCookie(w, h.cookie(h.cookieConfig.IDTokenName, rawIDToken))
	return tk, nil
}

func (h *webHandler) cookie(name, value string) *http.Cookie {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		Domain:   h.cookieConfig.Domain,
		Secure:   h.cookieConfig.Secure,
		HttpOnly: true,
	}
}

func (h *webHandler) deleteCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:   name,
		Path:   "/",
		MaxAge: -1,
		Domain: h.cookieConfig.Domain,
	})
}

func (h *webHandler) CleanCookies(w http.ResponseWriter) {
	h.deleteCookie(w, h.cookieConfig.IDTokenName)
	h.deleteCookie(w, h.cookieConfig.RefreshTokenName)
	h.deleteCookie(w, h.cookieConfig.RedirectName)
	h.deleteCookie(w, h.cookieConfig.AuthStateName)
}

func (h *webHandler) ensureCookieDomain(r *http.Request) {
	h.mu.RLock()
	if h.cookieConfig.Domain != "" {
		h.mu.RUnlock()
		return
	}
	h.mu.RUnlock()
	h.mu.Lock()
	h.cookieConfig.Domain = strings.Split(r.Host, ":")[0]
	h.mu.Unlock()
}
