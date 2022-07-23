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

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
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
	Verify(ctx context.Context) (*oidc.IDToken, error)
}

type grpcHandler struct {
	oauth oauth2.Config

	verifier *oidc.IDTokenVerifier
	log      logrus.FieldLogger
}

func (g *grpcHandler) UnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
		log := g.log.WithField("method", info.FullMethod)
		tk, err := g.Verify(ctx)
		if err != nil {
			log.WithError(err).Error("token validation failed")
			return nil, err
		}
		ctx = oidcContext(ctx, tk)
		return handler(ctx, req)
	}
}

func (g *grpcHandler) StreamServerInterceptor() grpc.StreamServerInterceptor {
	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		log := g.log.WithField("method", info.FullMethod)
		tk, err := g.Verify(ss.Context())
		if err != nil {
			log.WithError(err).Error("token validation failed")
			return err
		}
		ctx := oidcContext(ss.Context(), tk)
		return handler(srv, &sswrap{ss, ctx})
	}
}

func (g *grpcHandler) Verify(ctx context.Context) (*oidc.IDToken, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "no id token found in metadata")
	}
	a := md.Get("authorization")
	if len(a) < 1 {
		return nil, status.Error(codes.Unauthenticated, "no id token found in metadata")
	}
	if !strings.HasPrefix(strings.ToLower(a[0]), "bearer ") {
		return nil, status.Error(codes.Unauthenticated, "id token authorization must have the be 'Bearer [ID TOKEN]")
	}
	idToken, err := g.verifier.Verify(ctx, a[0][7:])
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}
	return idToken, nil
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
