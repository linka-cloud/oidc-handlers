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
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"go.linka.cloud/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

var (
	_ WebHandler = (*webHandler)(nil)
)

// Deprecated: use WebHandler instead
type Handler = WebHandler

// WebHandler is the oidc handler for standard web auth flow
type WebHandler interface {
	LoginHandler(w http.ResponseWriter, r *http.Request)
	LogoutHandler(w http.ResponseWriter, r *http.Request)
	RedirectHandler(w http.ResponseWriter, r *http.Request)
	CallbackHandler(w http.ResponseWriter, r *http.Request)
	Middleware(authPath string) func(r http.Handler) http.Handler
	Callback(w http.ResponseWriter, r *http.Request) error
	Refresh(w http.ResponseWriter, r *http.Request) (idToken string, err error)
	SetRedirectCookie(w http.ResponseWriter, path string)
	CleanCookies(w http.ResponseWriter)
}

// Deprecated: use Config.WebHandler instead
func New(ctx context.Context, config Config) (Handler, error) {
	config.Defaults()
	oauth2Config, verifier, endSession, err := config.apply(ctx)
	if err != nil {
		return nil, err
	}
	h := &webHandler{
		cookieConfig: config.CookieConfig,
		oauth:        oauth2Config,
		verifier:     verifier,
		now:          now,
		log:          config.Logger,
		endSession:   endSession,
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

	opts       func(ctx context.Context) []oauth2.AuthCodeOption
	endSession string
}

func (h *webHandler) SetRedirectCookie(w http.ResponseWriter, path string) {
	http.SetCookie(w, h.newCookie(h.cookieConfig.RedirectName, path))
}

func (h *webHandler) LoginHandler(w http.ResponseWriter, r *http.Request) {
	if _, err := h.Refresh(w, r); err == nil {
		path := "/"
		if c, err := h.cookie(r, h.cookieConfig.RedirectName); err == nil && c != "" {
			path = c
		} else if r := r.URL.Query().Get("redirect"); r != "" {
			path = r
		}
		http.Redirect(w, r, path, http.StatusSeeOther)
		return
	}
	h.RedirectHandler(w, r)
}

func (h *webHandler) Middleware(authPath string) func(r http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, authPath) {
				next.ServeHTTP(w, r)
				return
			}
			if _, err := h.Refresh(w, r); err != nil {
				h.SetRedirectCookie(w, r.URL.Path)
				http.Redirect(w, r, authPath, http.StatusSeeOther)
				return
			}
			// retrieve the id token and set it as authorization header for the next handlers
			tk, ok := RawIDTokenFromContext(r.Context())
			if !ok {
				panic("token refreshed but raw id token not in context")
			}
			r.Header.Set("Authorization", "Bearer "+tk)
			next.ServeHTTP(w, r)
		})
	}
}

func (h *webHandler) RedirectHandler(w http.ResponseWriter, r *http.Request) {
	log := h.log.WithField("path", r.URL.Path).WithField("method", r.Method)
	log.Info("redirect")
	h.ensureCookieDomain(r)
	state := newState()
	http.SetCookie(w, h.newCookie(h.cookieConfig.AuthStateName, state))
	http.Redirect(w, r, h.oauth.AuthCodeURL(state, h.opts(r.Context())...), http.StatusFound)
}

func (h *webHandler) Callback(w http.ResponseWriter, r *http.Request) error {
	log := h.log.WithField("path", r.URL.Path).WithField("method", r.Method)
	log.Info("callback")
	stateCookie, err := h.cookie(r, h.cookieConfig.AuthStateName)
	if err != nil {
		h.CleanCookies(w)
		return fmt.Errorf("state cookie: %w", err)
	}
	if r.URL.Query().Get("state") != stateCookie {
		return errors.New("invalid state cookie")
	}
	oauth2Token, err := h.oauth.Exchange(r.Context(), r.URL.Query().Get("code"), h.opts(r.Context())...)
	if err != nil {
		h.CleanCookies(w)
		return fmt.Errorf("no token: %w", err)
	}
	if _, _, err := h.handleOauthToken(r.Context(), w, oauth2Token); err != nil {
		h.CleanCookies(w)
		return fmt.Errorf("invalid token: %w", err)
	}
	path := "/"
	if c, err := h.cookie(r, h.cookieConfig.RedirectName); err == nil && c != "" {
		path = c
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
	idCookie, err := h.cookie(r, h.cookieConfig.IDTokenName)
	if err != nil {
		h.CleanCookies(w)
		return "", fmt.Errorf("oidc cookie: %w", err)
	}
	idToken, err := h.verifier.Verify(r.Context(), idCookie)
	if err != nil {
		log.WithError(err).Error("verify token")
		h.CleanCookies(w)
		return "", err
	}
	log = log.WithField("hash", idToken.AccessTokenHash)

	if !idToken.Expiry.Before(h.now().Add(idToken.Expiry.Sub(idToken.IssuedAt) / 2)) {
		log.Infof("skipping refresh (expiry: %v)", idToken.Expiry)
		*r = *r.WithContext(oidcContext(r.Context(), idToken, idCookie))
		return "", nil
	}
	refreshCookie, err := h.cookie(r, h.cookieConfig.RefreshTokenName)
	if err != nil {
		h.CleanCookies(w)
		log.WithError(err).Error("refresh cookie")
		return "", fmt.Errorf("refresh cookie: %w", err)
	}
	tk := h.oauth.TokenSource(r.Context(), &oauth2.Token{RefreshToken: refreshCookie, Expiry: idToken.Expiry})
	oauth2Token, err := tk.Token()
	if err != nil {
		log.WithError(err).Error("refresh token")
		return "", err
	}
	var rawIDToken string
	idToken, rawIDToken, err = h.handleOauthToken(r.Context(), w, oauth2Token)
	if err != nil {
		log.WithError(err).Error("handle token")
		return "", err
	}
	log.Info("token refreshed")
	*r = *r.WithContext(oidcContext(r.Context(), idToken, rawIDToken))
	return rawIDToken, nil
}

func (h *webHandler) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	if _, err := h.Refresh(w, r); err != nil {
		logrus.Error(err)
		h.CleanCookies(w)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	h.CleanCookies(w)
	if h.endSession == "" {
		w.WriteHeader(http.StatusOK)
		return
	}
	id, ok := RawIDTokenFromContext(r.Context())
	if !ok {
		logrus.Errorf("token refreshed but raw id token not in context")
		http.Error(w, "", http.StatusInternalServerError)
	}
	u, err := logoutURI(h.endSession, id)
	if err != nil {
		logrus.Errorf("end session url: %v", err)
		http.Error(w, "", http.StatusInternalServerError)
	}
	http.Redirect(w, r, u, http.StatusSeeOther)
}

func (h *webHandler) handleOauthToken(ctx context.Context, w http.ResponseWriter, oauth2Token *oauth2.Token) (*oidc.IDToken, string, error) {
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		return nil, "", errors.New("id_token not found")
	}

	tk, err := h.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, "", fmt.Errorf("verify token: %w", err)
	}
	http.SetCookie(w, h.newCookie(h.cookieConfig.RefreshTokenName, oauth2Token.RefreshToken))
	http.SetCookie(w, h.newCookie(h.cookieConfig.IDTokenName, rawIDToken))
	return tk, rawIDToken, nil
}

func (h *webHandler) newCookie(name, value string) *http.Cookie {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if h.cookieConfig.sec != nil {
		if v, err := h.cookieConfig.sec.Encode(name, value); err == nil {
			value = v
		}
	}
	return &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		Domain:   h.cookieConfig.Domain,
		Secure:   h.cookieConfig.Secure,
		HttpOnly: true,
	}
}

func (h *webHandler) cookie(r *http.Request, name string) (string, error) {
	c, err := r.Cookie(name)
	if err != nil {
		return "", err
	}
	if h.cookieConfig.sec == nil {
		return c.Value, nil
	}
	var v string
	if err := h.cookieConfig.sec.Decode(name, c.Value, &v); err != nil {
		return "", err
	}
	return v, nil
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
	// h.deleteCookie(w, h.cookieConfig.RedirectName)
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

func logoutURI(endSession string, rawIDToken string) (string, error) {
	u, err := url.Parse(endSession)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("id_token_hint", rawIDToken)
	u.RawQuery = q.Encode()
	return u.String(), nil
}
