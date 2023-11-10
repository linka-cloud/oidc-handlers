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

	"github.com/coreos/go-oidc/v3/oidc"
)

type claimsCtx struct{}
type idTokenCtx struct{}

type rawIDTokenCtx struct{}

func setClaims(ctx context.Context, idToken *oidc.IDToken) context.Context {
	if idToken == nil {
		return ctx
	}
	var claims Claims
	if err := idToken.Claims(&claims); err != nil {
		return ctx
	}
	return contextWithClaims(ctx, claims)
}

func contextWithClaims(ctx context.Context, claims Claims) context.Context {
	return context.WithValue(ctx, claimsCtx{}, claims)
}

func ClaimsFromContext(ctx context.Context) (Claims, bool) {
	v, ok := ctx.Value(claimsCtx{}).(Claims)
	return v, ok
}

func contextWithIDToken(ctx context.Context, idToken *oidc.IDToken) context.Context {
	if idToken == nil {
		return ctx
	}
	return context.WithValue(ctx, idTokenCtx{}, *idToken)
}

func IDTokenFromContext(ctx context.Context) (oidc.IDToken, bool) {
	v, ok := ctx.Value(idTokenCtx{}).(oidc.IDToken)
	return v, ok
}

func contextWithRawIDToken(ctx context.Context, rawIDToken string) context.Context {
	return context.WithValue(ctx, rawIDTokenCtx{}, rawIDToken)
}

func RawIDTokenFromContext(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(rawIDTokenCtx{}).(string)
	return v, ok
}

func oidcContext(ctx context.Context, idToken *oidc.IDToken, rawIDToken string) context.Context {
	return contextWithRawIDToken(contextWithIDToken(setClaims(ctx, idToken), idToken), rawIDToken)
}
