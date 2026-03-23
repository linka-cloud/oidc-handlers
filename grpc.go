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
	"strings"

	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"go.linka.cloud/grpc-toolkit/logger"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const (
	IDTokenMetadata = "oidc-idtoken"
	ClaimMetadata   = "oidc-claim"
)

var (
	_ GRPCHandler = (*grpcHandler)(nil)
)

type GRPCHandler interface {
	UnaryServerInterceptor() grpc.UnaryServerInterceptor
	StreamServerInterceptor() grpc.StreamServerInterceptor
	Verify(ctx context.Context) (*Token, string, error)
}

type grpcHandler struct {
	rp rp.RelyingParty
}

func (g *grpcHandler) UnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
		log := logger.C(ctx).WithField("oidc", "grpc").WithField("method", info.FullMethod)
		tk, raw, err := g.Verify(ctx)
		if err != nil {
			log.WithError(err).Error("token validation failed")
			return nil, err
		}
		ctx = oidcContext(ctx, tk, raw)
		return handler(ctx, req)
	}
}

func (g *grpcHandler) StreamServerInterceptor() grpc.StreamServerInterceptor {
	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		log := logger.C(ss.Context()).WithField("oidc", "grpc").WithField("method", info.FullMethod)
		tk, raw, err := g.Verify(ss.Context())
		if err != nil {
			log.WithError(err).Error("token validation failed")
			return err
		}
		ctx := oidcContext(ss.Context(), tk, raw)
		return handler(srv, &sswrap{ss, ctx})
	}
}

func (g *grpcHandler) Verify(ctx context.Context) (*Token, string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, "", unauth("no id token found in metadata")
	}
	a := md.Get("authorization")
	if len(a) < 1 {
		return nil, "", unauth("no id token found in metadata")
	}
	if !strings.HasPrefix(strings.ToLower(a[0]), "bearer ") {
		return nil, "", unauth("authorization must be 'Bearer [ID TOKEN]'")
	}
	raw := a[0][7:]
	idToken, err := rp.VerifyIDToken[*Token](ctx, raw, g.rp.IDTokenVerifier())
	if err != nil {
		logger.C(ctx).WithField("oidc", "grpc").WithError(err).Warn("verify id token")
		return nil, "", status.Error(codes.Unauthenticated, "unauthenticated")
	}
	return idToken, raw, nil
}

func unauth(msg string) error {
	return status.Error(codes.Unauthenticated, msg)
}

type sswrap struct {
	grpc.ServerStream
	ctx context.Context
}

func (w *sswrap) Context() context.Context {
	return w.ctx
}

func (w *sswrap) SetContext(ctx context.Context) {
	w.ctx = ctx
}
