package oidc_handlers

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
)

type Handler interface {
	RedirectHandler(w http.ResponseWriter, r *http.Request)
	CallbackHandler(w http.ResponseWriter, r *http.Request)
	Callback(w http.ResponseWriter, r *http.Request) error
	Refresh(w http.ResponseWriter, r *http.Request) (idToken string, err error)
	SetRedirectCookie(w http.ResponseWriter, path string)
	CleanCookies(w http.ResponseWriter)
}

const (
	DefaultIDTokenName      = "id_token"
	DefaultRefreshTokenName = "refresh_token"
	DefaultAuthStateName    = "auth_state"
	DefaultRedirectName     = "redirect"
)

func New(ctx context.Context, config Config) (Handler, error) {
	if len(config.Scopes) == 0 {
		config.Scopes = []string{oidc.ScopeOpenID, oidc.ScopeOfflineAccess, "profile", "email", "groups"}
	}
	if config.CookieConfig.RefreshTokenName == "" {
		config.CookieConfig.RefreshTokenName = DefaultRefreshTokenName
	}
	if config.CookieConfig.IDTokenName == "" {
		config.CookieConfig.IDTokenName = DefaultIDTokenName
	}
	if config.CookieConfig.AuthStateName == "" {
		config.CookieConfig.AuthStateName = DefaultAuthStateName
	}
	if config.CookieConfig.RedirectName == "" {
		config.CookieConfig.RedirectName = DefaultRedirectName
	}
	provider, err := oidc.NewProvider(ctx, config.IssuerURL)
	if err != nil {
		return nil, err
	}

	// Configure an OpenID Connect aware OAuth2 client.
	oauth2Config := oauth2.Config{
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		RedirectURL:  config.OauthCallback,
		Endpoint:     provider.Endpoint(),
		Scopes:       config.Scopes,
	}
	now := time.Now
	if config.Logger == nil {
		log := logrus.New()
		log.SetOutput(io.Discard)
		config.Logger = log
	}
	verifier := provider.Verifier(&oidc.Config{ClientID: config.ClientID, SkipExpiryCheck: true, Now: now})
	h := &handler{
		cookieConfig: config.CookieConfig,
		oauth:        oauth2Config,
		verifier:     verifier,
		now:          now,
		log:          config.Logger,
	}
	return h, nil
}

type handler struct {
	oauth        oauth2.Config
	cookieConfig CookieConfig

	verifier *oidc.IDTokenVerifier
	log      logrus.FieldLogger

	now      func() time.Time
	m        sync.Map
	mu       sync.RWMutex
}

func (h *handler) SetRedirectCookie(w http.ResponseWriter, path string) {
	http.SetCookie(w, h.cookie(h.cookieConfig.RedirectName, path))
}

func (h *handler) RedirectHandler(w http.ResponseWriter, r *http.Request) {
	h.ensureCookieDomain(r)
	state := newState()
	http.SetCookie(w, h.cookie(h.cookieConfig.AuthStateName, state))
	http.Redirect(w, r, h.oauth.AuthCodeURL(state), http.StatusFound)
}

func (h *handler) Callback(w http.ResponseWriter, r *http.Request) error {
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

func (h *handler) CallbackHandler(w http.ResponseWriter, r *http.Request) {
	if err := h.Callback(w, r); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
}

func (h *handler) Refresh(w http.ResponseWriter, r *http.Request) (string, error) {
	h.ensureCookieDomain(r)
	idCookie, err := r.Cookie(h.cookieConfig.IDTokenName)
	if err != nil {
		h.CleanCookies(w)
		return "", fmt.Errorf("oidc cookie: %w", err)
	}
	idToken, err := h.verifier.Verify(r.Context(), idCookie.Value)
	if err != nil {
		h.log.WithError(err).Error("verify token")
		h.CleanCookies(w)
		return "", err
	}
	log := h.log.WithField("hash", idToken.AccessTokenHash)
	key := idToken.AccessTokenHash
	_, refreshing := h.m.Load(key)
	if !idToken.Expiry.Before(h.now().Add(5*time.Second)) || refreshing {
		if refreshing {
			log.Warn("token is refreshing")
		}
		log.Infof("skipping refresh (expiry: %v)", idToken.Expiry)
		*r = *r.WithContext(setClaims(r.Context(), idToken))
		return "", nil
	}
	h.m.Store(key, struct{}{})
	log.Infof("setting refreshing marker")
	defer time.AfterFunc(time.Second, func() {
		log.Infof("deleting refreshing marker")
		h.m.Delete(key)
	})
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
	*r = *r.WithContext(setClaims(r.Context(), idToken))
	return oauth2Token.Extra("id_token").(string), nil
}

func (h *handler) handleOauthToken(ctx context.Context, w http.ResponseWriter, oauth2Token *oauth2.Token) (*oidc.IDToken, error) {
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

func setClaims(ctx context.Context, idToken *oidc.IDToken) context.Context {
	var claims Claims
	if err := idToken.Claims(&claims); err != nil {
		return ctx
	}
	return contextWithClaims(ctx, claims)
}

func (h *handler) cookie(name, value string) *http.Cookie {
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

func (h *handler) deleteCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:   name,
		Path:   "/",
		MaxAge: -1,
		Domain: h.cookieConfig.Domain,
	})
}

func (h *handler) CleanCookies(w http.ResponseWriter) {
	h.deleteCookie(w, h.cookieConfig.IDTokenName)
	h.deleteCookie(w, h.cookieConfig.RefreshTokenName)
	h.deleteCookie(w, h.cookieConfig.RedirectName)
	h.deleteCookie(w, h.cookieConfig.AuthStateName)
}

func (h *handler) ensureCookieDomain(r *http.Request) {
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
