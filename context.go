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
