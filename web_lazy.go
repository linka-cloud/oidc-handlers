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
	"net/http"
	"sync"

	"go.linka.cloud/grpc-toolkit/logger"
)

type lazyWebHandler struct {
	ctx    context.Context
	config *Config
	h      WebHandler
	mu     sync.RWMutex
}

func (l *lazyWebHandler) LoginHandler(w http.ResponseWriter, r *http.Request) {
	h, err := l.handlerOr503(w)
	if err != nil {
		return
	}
	h.LoginHandler(w, r)
}

func (l *lazyWebHandler) RedirectHandler(w http.ResponseWriter, r *http.Request) {
	h, err := l.handlerOr503(w)
	if err != nil {
		return
	}
	h.RedirectHandler(w, r)
}

func (l *lazyWebHandler) CallbackHandler(w http.ResponseWriter, r *http.Request) {
	h, err := l.handlerOr503(w)
	if err != nil {
		return
	}
	h.CallbackHandler(w, r)
}

func (l *lazyWebHandler) Callback(w http.ResponseWriter, r *http.Request) error {
	h, err := l.handlerOr503(w)
	if err != nil {
		return err
	}
	return h.Callback(w, r)
}

func (l *lazyWebHandler) Refresh(w http.ResponseWriter, r *http.Request) (idToken string, err error) {
	h, err := l.handler()
	if err != nil {
		return "", err
	}
	return h.Refresh(w, r)
}

func (l *lazyWebHandler) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	h, err := l.handlerOr503(w)
	if err != nil {
		return
	}
	h.LogoutHandler(w, r)
}

func (l *lazyWebHandler) Middleware(authPath string) func(r http.Handler) http.Handler {
	h, err := l.handler()
	if err == nil {
		return h.Middleware(authPath)
	}
	var (
		mu   sync.RWMutex
		mldw http.Handler
	)
	mk := func(next http.Handler) (http.Handler, bool) {
		mu.RLock()
		if mldw != nil {
			mu.RUnlock()
			return mldw, true
		}
		mu.RUnlock()
		h, err := l.handler()
		if err != nil {
			return nil, false
		}
		mu.Lock()
		mldw = h.Middleware(authPath)(next)
		mu.Unlock()
		return mldw, true
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if h, ok := mk(next); ok {
				h.ServeHTTP(w, r)
				return
			}
			http.Error(w, "", http.StatusServiceUnavailable)
		})
	}
}

func (l *lazyWebHandler) SetRedirectCookie(w http.ResponseWriter, path string) {
	h, err := l.handlerOr503(w)
	if err != nil {
		return
	}
	h.SetRedirectCookie(w, path)
}

func (l *lazyWebHandler) CleanCookies(w http.ResponseWriter) {
	h, err := l.handlerOr503(w)
	if err != nil {
		return
	}
	h.CleanCookies(w)
}

func (l *lazyWebHandler) handlerOr503(w http.ResponseWriter) (WebHandler, error) {
	h, err := l.handler()
	if err == nil {
		return h, nil
	}
	http.Error(w, "", http.StatusServiceUnavailable)
	return nil, err
}

func (l *lazyWebHandler) handler() (WebHandler, error) {
	l.mu.RLock()
	if l.h != nil {
		l.mu.RUnlock()
		return l.h, nil
	}
	l.mu.RUnlock()

	l.mu.Lock()
	defer l.mu.Unlock()
	if l.h != nil {
		return l.h, nil
	}

	var err error
	if l.h, err = l.config.WebHandler(l.ctx); err != nil {
		logger.C(l.ctx).WithField("oidc", "web").WithError(err).Error("handler init failed")
	}
	return l.h, err
}
