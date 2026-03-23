package oidc_handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"golang.org/x/oauth2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestNewState(t *testing.T) {
	t.Parallel()

	allowed := regexp.MustCompile(`^[a-zA-Z0-9]+$`)
	seen := map[string]struct{}{}
	for i := 0; i < 256; i++ {
		s, err := newStateWithErr()
		if err != nil {
			t.Fatalf("new state: %v", err)
		}
		if len(s) != 32 {
			t.Fatalf("invalid state length %d", len(s))
		}
		if !allowed.MatchString(s) {
			t.Fatalf("state has invalid chars: %q", s)
		}
		if _, ok := seen[s]; ok {
			t.Fatalf("duplicate state generated: %q", s)
		}
		seen[s] = struct{}{}
	}
}

func TestSanitizeRedirectPath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in   string
		want string
	}{
		{in: "/app", want: "/app"},
		{in: "", want: "/"},
		{in: "http://evil.test", want: "/"},
		{in: "//evil.test", want: "/"},
		{in: "javascript:alert(1)", want: "/"},
		{in: "not/absolute", want: "/"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := cleanRedirect(tt.in); got != tt.want {
				t.Fatalf("cleanRedirect(%q)=%q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestCookieRoundTripAndTamper(t *testing.T) {
	t.Parallel()

	c := CookieConfig{Key: "secret-key"}
	c.Defaults()
	h := &webHandler{cookieConfig: c}
	enc := h.newCookie(c.IDTokenName, "secret")
	if enc.SameSite != http.SameSiteLaxMode {
		t.Fatalf("expected SameSiteLaxMode, got %v", enc.SameSite)
	}
	if enc.Value == "secret" {
		t.Fatal("cookie value should be encoded when key is set")
	}

	r := httptest.NewRequest(http.MethodGet, "http://example.test", nil)
	r.AddCookie(enc)
	v, err := h.cookie(r, c.IDTokenName)
	if err != nil {
		t.Fatalf("decode cookie: %v", err)
	}
	if v != "secret" {
		t.Fatalf("invalid decoded value: %q", v)
	}

	tampered := *enc
	tampered.Value = enc.Value + "x"
	r2 := httptest.NewRequest(http.MethodGet, "http://example.test", nil)
	r2.AddCookie(&tampered)
	if _, err := h.cookie(r2, c.IDTokenName); err == nil {
		t.Fatal("expected decode error for tampered cookie")
	}
}

func TestCallbackRejectsInvalidState(t *testing.T) {
	t.Parallel()

	c := CookieConfig{}
	c.Defaults()
	h := &webHandler{
		cookieConfig: c,
		opts:         func(context.Context) []oauth2.AuthCodeOption { return nil },
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "http://example.test/auth/callback?state=bad&code=ignored", nil)
	r.AddCookie(h.newCookie(c.AuthStateName, "good"))

	err := h.Callback(w, r)
	if err == nil {
		t.Fatal("expected state validation error")
	}
	if !strings.Contains(err.Error(), "invalid state cookie") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCallbackHandlerHidesInternalError(t *testing.T) {
	t.Parallel()

	c := CookieConfig{}
	c.Defaults()
	h := &webHandler{
		cookieConfig: c,
		opts:         func(context.Context) []oauth2.AuthCodeOption { return nil },
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "http://example.test/auth/callback?state=bad&code=ignored", nil)
	r.AddCookie(h.newCookie(c.AuthStateName, "good"))

	h.CallbackHandler(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("unexpected status: %d", w.Code)
	}
	body := w.Body.String()
	if strings.Contains(body, "invalid state cookie") {
		t.Fatalf("response leaks internal detail: %q", body)
	}
	if !strings.Contains(body, "bad request") {
		t.Fatalf("unexpected response body: %q", body)
	}
}

func TestHandleOauthTokenRejectsMissingIDToken(t *testing.T) {
	t.Parallel()

	h := &webHandler{cookieConfig: CookieConfig{}}
	w := httptest.NewRecorder()
	tk := &oauth2.Token{AccessToken: "access", RefreshToken: "refresh"}

	_, _, err := h.handleToken(context.Background(), w, tk)
	if err == nil {
		t.Fatal("expected missing id_token error")
	}
	if !strings.Contains(err.Error(), "id_token not found") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGRPCVerifyRejectsInvalidAuthorization(t *testing.T) {
	t.Parallel()

	h := &grpcHandler{}
	tests := []struct {
		name string
		ctx  context.Context
	}{
		{name: "no metadata", ctx: context.Background()},
		{name: "missing authorization", ctx: metadata.NewIncomingContext(context.Background(), metadata.Pairs("x", "y"))},
		{name: "wrong scheme", ctx: metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Basic token"))},
		{name: "missing bearer space", ctx: metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer"))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := h.Verify(tt.ctx)
			if err == nil {
				t.Fatal("expected unauthenticated error")
			}
			if status.Code(err) != codes.Unauthenticated {
				t.Fatalf("expected unauthenticated, got: %v", status.Code(err))
			}
		})
	}
}

func TestOIDCContextRoundTrip(t *testing.T) {
	t.Parallel()

	tk := &Token{Name: "name", Email: "mail@example.com", Verified: true, Groups: []string{"dev"}}
	tk.Subject = "user-1"
	ctx := oidcContext(context.Background(), tk, "raw-token")

	claims, ok := ClaimsFromContext(ctx)
	if !ok {
		t.Fatal("claims not found")
	}
	if claims.ID != "user-1" || claims.Email != "mail@example.com" || !claims.Verified {
		t.Fatalf("unexpected claims: %+v", claims)
	}

	raw, ok := RawIDTokenFromContext(ctx)
	if !ok || raw != "raw-token" {
		t.Fatalf("unexpected raw token: %q", raw)
	}

	g, ok := IDTokenFromContext(ctx)
	if !ok || g.GetSubject() != "user-1" {
		t.Fatalf("unexpected id token: %+v", g)
	}
}
