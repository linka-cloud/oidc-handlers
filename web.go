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
	"time"

	"github.com/sirupsen/logrus"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
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
	rp, err := config.newRP(ctx)
	if err != nil {
		return nil, err
	}
	h := &webHandler{
		cookieConfig: config.CookieConfig,
		rp:           rp,
		now:          now,
		log:          config.Logger,
		opts:         config.Opts,
	}
	return h, nil
}

type webHandler struct {
	cookieConfig CookieConfig

	rp  rp.RelyingParty
	log logrus.FieldLogger

	now func() time.Time

	opts func(ctx context.Context) []oauth2.AuthCodeOption
}

func (h *webHandler) SetRedirectCookie(w http.ResponseWriter, path string) {
	http.SetCookie(w, h.newCookie(h.cookieConfig.RedirectName, cleanRedirect(path)))
}

func (h *webHandler) LoginHandler(w http.ResponseWriter, r *http.Request) {
	if _, err := h.Refresh(w, r); err == nil {
		http.Redirect(w, r, h.nextPath(r), http.StatusSeeOther)
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
				h.CleanCookies(w)
				http.Redirect(w, r, authPath, http.StatusSeeOther)
				return
			}
			r.Header.Set("Authorization", "Bearer "+tk)
			next.ServeHTTP(w, r)
		})
	}
}

func (h *webHandler) RedirectHandler(w http.ResponseWriter, r *http.Request) {
	log := h.logReq(r)
	log.Info("redirect")
	state, err := newStateWithErr()
	if err != nil {
		log.WithError(err).Error("state generation failed")
		http.Error(w, "", http.StatusServiceUnavailable)
		return
	}
	http.SetCookie(w, h.newCookie(h.cookieConfig.AuthStateName, state))
	http.Redirect(w, r, h.rp.OAuthConfig().AuthCodeURL(state, h.opts(r.Context())...), http.StatusFound)
}

func (h *webHandler) Callback(w http.ResponseWriter, r *http.Request) error {
	log := h.logReq(r)
	log.Info("callback")
	stateCookie, err := h.cookie(r, h.cookieConfig.AuthStateName)
	if err != nil {
		h.CleanCookies(w)
		return fmt.Errorf("state cookie: %w", err)
	}
	if r.URL.Query().Get("state") != stateCookie {
		return errors.New("invalid state cookie")
	}
	oauth2Token, err := h.rp.OAuthConfig().Exchange(r.Context(), r.URL.Query().Get("code"), h.opts(r.Context())...)
	if err != nil {
		h.CleanCookies(w)
		return fmt.Errorf("no token: %w", err)
	}
	if _, _, err := h.handleToken(r.Context(), w, oauth2Token); err != nil {
		h.CleanCookies(w)
		return fmt.Errorf("invalid token: %w", err)
	}
	path := h.nextPath(r)
	h.deleteCookie(w, h.cookieConfig.AuthStateName)
	h.deleteCookie(w, h.cookieConfig.RedirectName)
	http.Redirect(w, r, path, http.StatusSeeOther)
	return nil
}

func (h *webHandler) CallbackHandler(w http.ResponseWriter, r *http.Request) {
	if err := h.Callback(w, r); err != nil {
		h.log.WithError(err).Warn("callback failed")
		http.Error(w, "bad request", http.StatusBadRequest)
	}
}

func (h *webHandler) Refresh(w http.ResponseWriter, r *http.Request) (string, error) {
	log := h.logReq(r)
	log.Info("refresh")
	idCookie, err := h.cookie(r, h.cookieConfig.IDTokenName)
	if err != nil {
		h.CleanCookies(w)
		return "", fmt.Errorf("oidc cookie: %w", err)
	}
	idToken, err := rp.VerifyIDToken[*Token](r.Context(), idCookie, h.rp.IDTokenVerifier())
	if err == nil {
		log = log.WithField("hash", idToken.GetAccessTokenHash())
		expiry := idToken.GetExpiration()
		issuedAt := idToken.GetIssuedAt()
		if !expiry.Before(h.now().Add(expiry.Sub(issuedAt) / 2)) {
			log.Infof("skipping refresh (expiry: %v)", expiry)
			*r = *r.WithContext(oidcContext(r.Context(), idToken, idCookie))
			return "", nil
		}
	} else {
		log.WithError(err).Warn("verify token, forcing refresh")
	}
	refreshCookie, err := h.cookie(r, h.cookieConfig.RefreshTokenName)
	if err != nil {
		h.CleanCookies(w)
		log.WithError(err).Error("refresh cookie")
		return "", fmt.Errorf("refresh cookie: %w", err)
	}
	tks, err := rp.RefreshTokens[*Token](r.Context(), h.rp, refreshCookie, "", "")
	if err != nil {
		log.WithError(err).Error("refresh token")
		return "", err
	}
	refreshToken := pickRefresh(tks.RefreshToken, refreshCookie)
	idToken = tks.IDTokenClaims
	rawIDToken := tks.IDToken
	if idToken == nil || rawIDToken == "" {
		log.WithError(errors.New("id_token not found")).Error("refresh token")
		return "", errors.New("id_token not found")
	}
	h.setCookies(w, rawIDToken, refreshToken)
	log.Info("token refreshed")
	*r = *r.WithContext(oidcContext(r.Context(), idToken, rawIDToken))
	return rawIDToken, nil
}

func (h *webHandler) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	log := h.logReq(r)
	if _, err := h.Refresh(w, r); err != nil {
		log.WithError(err).Error("refresh before logout")
		h.CleanCookies(w)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	h.CleanCookies(w)
	if h.rp.GetEndSessionEndpoint() == "" {
		w.WriteHeader(http.StatusOK)
		return
	}
	id, ok := RawIDTokenFromContext(r.Context())
	if !ok {
		log.Error("token refreshed but raw id token not in context")
		http.Error(w, "", http.StatusInternalServerError)
		return
	}
	endSession, err := logoutURI(h.rp.GetEndSessionEndpoint(), id)
	if err != nil {
		log.WithError(err).Error("end session url")
		http.Error(w, "", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, endSession, http.StatusSeeOther)
}

func (h *webHandler) handleToken(ctx context.Context, w http.ResponseWriter, oauth2Token *oauth2.Token) (*Token, string, error) {
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		return nil, "", errors.New("id_token not found")
	}

	tk, err := rp.VerifyTokens[*Token](ctx, oauth2Token.AccessToken, rawIDToken, h.rp.IDTokenVerifier())
	if err != nil {
		return nil, "", fmt.Errorf("verify token: %w", err)
	}
	h.setCookies(w, rawIDToken, oauth2Token.RefreshToken)
	return tk, rawIDToken, nil
}

func (h *webHandler) setCookies(w http.ResponseWriter, idToken, refreshToken string) {
	if refreshToken != "" {
		http.SetCookie(w, h.newCookie(h.cookieConfig.RefreshTokenName, refreshToken))
	}
	if idToken != "" {
		http.SetCookie(w, h.newCookie(h.cookieConfig.IDTokenName, idToken))
	}
}

func (h *webHandler) newCookie(name, value string) *http.Cookie {
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
		SameSite: http.SameSiteLaxMode,
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
		Name:     name,
		Path:     "/",
		MaxAge:   -1,
		Domain:   h.cookieConfig.Domain,
		Secure:   h.cookieConfig.Secure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func (h *webHandler) CleanCookies(w http.ResponseWriter) {
	h.deleteCookie(w, h.cookieConfig.IDTokenName)
	h.deleteCookie(w, h.cookieConfig.RefreshTokenName)
	h.deleteCookie(w, h.cookieConfig.RedirectName)
	h.deleteCookie(w, h.cookieConfig.AuthStateName)
}

func (h *webHandler) nextPath(r *http.Request) string {
	if c, err := h.cookie(r, h.cookieConfig.RedirectName); err == nil && c != "" {
		return cleanRedirect(c)
	}
	rd := r.URL.Query().Get("redirect")
	if rd == "" {
		return "/"
	}
	return cleanRedirect(rd)
}

func cleanRedirect(path string) string {
	if path == "" || !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") {
		return "/"
	}
	u, err := url.Parse(path)
	if err != nil || u.IsAbs() {
		return "/"
	}
	return path
}

func (h *webHandler) logReq(r *http.Request) *logrus.Entry {
	return h.log.WithField("path", r.URL.Path).WithField("method", r.Method)
}
