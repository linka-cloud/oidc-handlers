package oidc_handlers

import (
	"context"
	"sync"

	"github.com/coreos/go-oidc/v3/oidc"
	"google.golang.org/grpc"
)

type lazyGRPCHandler struct {
	ctx    context.Context
	config *Config
	mu     sync.RWMutex
	h      GRPCHandler
}

func (l *lazyGRPCHandler) UnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
		h, err := l.handler()
		if err != nil {
			return nil, err
		}
		return h.UnaryServerInterceptor()(ctx, req, info, handler)
	}
}

func (l *lazyGRPCHandler) StreamServerInterceptor() grpc.StreamServerInterceptor {
	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		h, err := l.handler()
		if err != nil {
			return err
		}
		return h.StreamServerInterceptor()(srv, ss, info, handler)
	}
}

func (l *lazyGRPCHandler) Verify(ctx context.Context) (*oidc.IDToken, error) {
	h, err := l.handler()
	if err != nil {
		return nil, err
	}
	return h.Verify(ctx)
}

func (l *lazyGRPCHandler) handler() (GRPCHandler, error) {
	l.mu.RLock()
	if l.h != nil {
		l.mu.RUnlock()
		return l.h, nil
	}
	l.mu.RUnlock()
	l.mu.Lock()
	defer l.mu.Unlock()
	var err error
	l.h, err = l.config.GRPC(l.ctx)
	if err != nil {
		return nil, err
	}
	return l.h, nil
}
