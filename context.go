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
)

type claimsCtx struct{}

func contextWithClaims(ctx context.Context, claims Claims) context.Context {
	return context.WithValue(ctx, claimsCtx{}, claims)
}

func ClaimsFromContext(ctx context.Context) (Claims, bool) {
	v := ctx.Value(claimsCtx{})
	c, ok := v.(Claims)
	return c, ok
}
