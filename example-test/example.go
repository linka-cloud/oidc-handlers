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

package main

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"

	oidch "go.linka.cloud/oidc-handlers"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	config := oidch.Config{
		IssuerURL:     "http://oidc.test:5556",
		ClientID:      "oidc",
		ClientSecret:  "0TJ3992YlriTfyuTgcO81L8b6eZWlWwKC2Gqij5nR44",
		OauthCallback: "http://app.oidc.test:8888/auth/callback",
		CookieConfig: oidch.CookieConfig{
			Key: "secret-key",
		},
	}
	devCtx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()

	go func() {
		// Perform single device auth flow
		if err := device(devCtx, config); err != nil {
			logrus.Error(err)
		}
	}()
	// Start web app
	if err := web(ctx, config); err != nil {
		logrus.Fatal(err)
	}
}

func device(ctx context.Context, config oidch.Config) error {
	dh, err := config.DeviceHandler(ctx)
	if err != nil {
		return err
	}
	v, err := dh.Exchange(ctx)
	if err != nil {
		return err
	}
	logrus.Infof("Please visit %s to authenticate", v.URI())
	if _, _, _, err := v.Verify(ctx); err != nil {
		return err
	}
	logrus.Infof("Device authentication succeed")
	return nil
}

func web(ctx context.Context, config oidch.Config) error {
	oidc, err := config.WebHandler(ctx)
	if err != nil {
		return err
	}
	http.HandleFunc("/auth", oidc.RedirectHandler)
	http.HandleFunc("/auth/callback", oidc.CallbackHandler)
	http.HandleFunc("/logout", oidc.LogoutHandler)
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if _, err := oidc.Refresh(w, r); err != nil {
			logrus.Error(err)
			oidc.SetRedirectCookie(w, "/")
			http.Redirect(w, r, "/auth", http.StatusSeeOther)
			return
		}
		c, ok := oidch.ClaimsFromContext(r.Context())
		if !ok {
			http.Error(w, "no claims found", http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(c)
	})
	lm := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			logrus.WithFields(logrus.Fields{"path": r.URL.Path, "method": r.Method, "remote": r.RemoteAddr}).Info("new request")
			next.ServeHTTP(w, r)
		})
	}
	logrus.Info("Starting web server at http://app.oidc.test:8888")
	return http.ListenAndServe(":8888", lm(http.DefaultServeMux))
}
