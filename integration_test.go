package oidc_handlers

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type fakeOP struct {
	t *testing.T

	server *httptest.Server
	issuer string
	endURL string

	key        *rsa.PrivateKey
	clientID   string
	refreshNew string

	codeIDToken    string
	refreshIDToken string

	includeRefresh bool
	includeIDToken bool
	requireHint    bool
	lastHint       string
}

func newFakeOP(t *testing.T, clientID string) *fakeOP {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	op := &fakeOP{t: t, key: key, clientID: clientID, includeRefresh: true, includeIDToken: true}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", op.discovery)
	mux.HandleFunc("/keys", op.keys)
	mux.HandleFunc("/token", op.token)
	mux.HandleFunc("/logout", op.logout)
	op.server = httptest.NewServer(mux)
	op.issuer = op.server.URL
	op.endURL = op.server.URL + "/logout"
	op.codeIDToken = op.sign("user-1", time.Now().Add(time.Hour), time.Now())
	op.refreshIDToken = op.sign("user-1", time.Now().Add(time.Hour), time.Now())
	op.refreshNew = "refresh-new"
	t.Cleanup(op.server.Close)
	return op
}

func (f *fakeOP) sign(sub string, exp, iat time.Time) string {
	f.t.Helper()
	s, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: &jose.JSONWebKey{KeyID: "k1", Key: f.key}}, nil)
	if err != nil {
		f.t.Fatalf("new signer: %v", err)
	}
	claims := map[string]any{
		"iss": f.issuer,
		"sub": sub,
		"aud": []string{f.clientID},
		"exp": exp.Unix(),
		"iat": iat.Unix(),
	}
	b, err := json.Marshal(claims)
	if err != nil {
		f.t.Fatalf("marshal claims: %v", err)
	}
	o, err := s.Sign(b)
	if err != nil {
		f.t.Fatalf("sign token: %v", err)
	}
	tk, err := o.CompactSerialize()
	if err != nil {
		f.t.Fatalf("compact token: %v", err)
	}
	return tk
}

func (f *fakeOP) discovery(w http.ResponseWriter, r *http.Request) {
	_ = json.NewEncoder(w).Encode(map[string]any{
		"issuer":                 f.issuer,
		"authorization_endpoint": f.issuer + "/auth",
		"token_endpoint":         f.issuer + "/token",
		"jwks_uri":               f.issuer + "/keys",
		"end_session_endpoint":   f.endURL,
	})
}

func (f *fakeOP) keys(w http.ResponseWriter, r *http.Request) {
	set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{KeyID: "k1", Algorithm: string(jose.RS256), Use: "sig", Key: f.key.Public()}}}
	_ = json.NewEncoder(w).Encode(set)
}

func (f *fakeOP) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	grant := r.Form.Get("grant_type")
	resp := map[string]any{"access_token": "access", "token_type": "Bearer", "expires_in": 3600}
	if grant == "authorization_code" || r.Form.Get("code") != "" {
		resp["id_token"] = f.codeIDToken
		resp["refresh_token"] = "refresh-init"
		_ = json.NewEncoder(w).Encode(resp)
		return
	}
	if grant == "refresh_token" {
		if f.includeIDToken {
			resp["id_token"] = f.refreshIDToken
		}
		if f.includeRefresh {
			resp["refresh_token"] = f.refreshNew
		}
		_ = json.NewEncoder(w).Encode(resp)
		return
	}
	http.Error(w, "unsupported grant", http.StatusBadRequest)
}

func (f *fakeOP) logout(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	f.lastHint = r.Form.Get("id_token_hint")
	if f.requireHint && f.lastHint == "" {
		http.Error(w, "missing id_token_hint", http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func cookieValue(cookies []*http.Cookie, name string) string {
	for _, c := range cookies {
		if c.Name == name {
			return c.Value
		}
	}
	return ""
}

func TestCallbackAndMiddlewareSuccess(t *testing.T) {
	op := newFakeOP(t, "client")
	c := Config{IssuerURL: op.issuer, ClientID: "client", ClientSecret: "secret", OauthCallback: "http://app.test/auth/callback"}
	hh, err := c.WebHandler(context.Background())
	if err != nil {
		t.Fatalf("create handler: %v", err)
	}
	h := hh.(*webHandler)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "http://app.test/auth/callback?state=s1&code=c1", nil)
	r.AddCookie(h.newCookie(h.cookieConfig.AuthStateName, "s1"))
	r.AddCookie(h.newCookie(h.cookieConfig.RedirectName, "/target"))

	err = h.Callback(w, r)
	if err != nil {
		t.Fatalf("callback failed: %v", err)
	}
	if w.Code != http.StatusSeeOther {
		t.Fatalf("unexpected status: %d", w.Code)
	}
	if got := w.Header().Get("Location"); got != "/target" {
		t.Fatalf("unexpected redirect location: %q", got)
	}

	respCookies := w.Result().Cookies()
	id := cookieValue(respCookies, h.cookieConfig.IDTokenName)
	if id == "" {
		t.Fatal("id token cookie not set")
	}
	refresh := cookieValue(respCookies, h.cookieConfig.RefreshTokenName)
	if refresh == "" {
		t.Fatal("refresh token cookie not set")
	}

	var gotAuth string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	})
	m := h.Middleware("/auth")(next)
	w2 := httptest.NewRecorder()
	r2 := httptest.NewRequest(http.MethodGet, "http://app.test/", nil)
	r2.AddCookie(&http.Cookie{Name: h.cookieConfig.IDTokenName, Value: id})
	r2.AddCookie(&http.Cookie{Name: h.cookieConfig.RefreshTokenName, Value: refresh})
	m.ServeHTTP(w2, r2)
	if w2.Code != http.StatusOK {
		t.Fatalf("unexpected middleware status: %d", w2.Code)
	}
	if !strings.HasPrefix(gotAuth, "Bearer ") {
		t.Fatalf("missing bearer auth header: %q", gotAuth)
	}
}

func TestRefreshFallsBackToOldRefreshToken(t *testing.T) {
	op := newFakeOP(t, "client")
	op.includeRefresh = false
	oldRefresh := "refresh-old"
	op.refreshIDToken = op.sign("user-1", time.Now().Add(time.Hour), time.Now().Add(-time.Hour))
	id := op.sign("user-1", time.Now().Add(time.Minute), time.Now().Add(-time.Hour))

	c := Config{IssuerURL: op.issuer, ClientID: "client", ClientSecret: "secret", OauthCallback: "http://app.test/auth/callback"}
	hh, err := c.WebHandler(context.Background())
	if err != nil {
		t.Fatalf("create handler: %v", err)
	}
	h := hh.(*webHandler)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "http://app.test/", nil)
	r.AddCookie(&http.Cookie{Name: h.cookieConfig.IDTokenName, Value: id})
	r.AddCookie(&http.Cookie{Name: h.cookieConfig.RefreshTokenName, Value: oldRefresh})

	gotID, err := h.Refresh(w, r)
	if err != nil {
		t.Fatalf("refresh failed: %v", err)
	}
	if gotID == "" {
		t.Fatal("expected refreshed id token")
	}
	if got := cookieValue(w.Result().Cookies(), h.cookieConfig.RefreshTokenName); got != oldRefresh {
		t.Fatalf("expected old refresh token fallback, got %q", got)
	}
}

func TestRefreshRejectsMissingRefreshedIDToken(t *testing.T) {
	op := newFakeOP(t, "client")
	op.includeIDToken = false
	id := op.sign("user-1", time.Now().Add(time.Minute), time.Now().Add(-time.Hour))

	c := Config{IssuerURL: op.issuer, ClientID: "client", ClientSecret: "secret", OauthCallback: "http://app.test/auth/callback"}
	hh, err := c.WebHandler(context.Background())
	if err != nil {
		t.Fatalf("create handler: %v", err)
	}
	h := hh.(*webHandler)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "http://app.test/", nil)
	r.AddCookie(&http.Cookie{Name: h.cookieConfig.IDTokenName, Value: id})
	r.AddCookie(&http.Cookie{Name: h.cookieConfig.RefreshTokenName, Value: "refresh-old"})

	_, err = h.Refresh(w, r)
	if err == nil {
		t.Fatal("expected refresh error when id_token is missing")
	}
	if !strings.Contains(err.Error(), "id_token not found") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRefreshExpiredIDTokenStillUsesRefreshToken(t *testing.T) {
	op := newFakeOP(t, "client")
	op.refreshIDToken = op.sign("user-1", time.Now().Add(time.Hour), time.Now().Add(-time.Hour))
	id := op.sign("user-1", time.Now().Add(-time.Minute), time.Now().Add(-time.Hour))

	c := Config{IssuerURL: op.issuer, ClientID: "client", ClientSecret: "secret", OauthCallback: "http://app.test/auth/callback"}
	hh, err := c.WebHandler(context.Background())
	if err != nil {
		t.Fatalf("create handler: %v", err)
	}
	h := hh.(*webHandler)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "http://app.test/", nil)
	r.AddCookie(&http.Cookie{Name: h.cookieConfig.IDTokenName, Value: id})
	r.AddCookie(&http.Cookie{Name: h.cookieConfig.RefreshTokenName, Value: "refresh-old"})

	gotID, err := h.Refresh(w, r)
	if err != nil {
		t.Fatalf("refresh failed: %v", err)
	}
	if gotID == "" {
		t.Fatal("expected refreshed id token")
	}
}

func TestGRPCVerifySuccess(t *testing.T) {
	op := newFakeOP(t, "client")
	id := op.sign("user-1", time.Now().Add(time.Hour), time.Now())

	c := Config{IssuerURL: op.issuer, ClientID: "client", ClientSecret: "secret", OauthCallback: "http://app.test/auth/callback"}
	h, err := c.GRPC(context.Background())
	if err != nil {
		t.Fatalf("create grpc handler: %v", err)
	}

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+id))
	tk, raw, err := h.Verify(ctx)
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if raw == "" || tk.GetSubject() != "user-1" {
		t.Fatalf("unexpected verification result: raw=%q sub=%q", raw, tk.GetSubject())
	}
}

func TestGRPCVerifyInvalidTokenHidesDetail(t *testing.T) {
	op := newFakeOP(t, "client")

	c := Config{IssuerURL: op.issuer, ClientID: "client", ClientSecret: "secret", OauthCallback: "http://app.test/auth/callback"}
	h, err := c.GRPC(context.Background())
	if err != nil {
		t.Fatalf("create grpc handler: %v", err)
	}

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer invalid.token.value"))
	_, _, err = h.Verify(ctx)
	if err == nil {
		t.Fatal("expected verify error")
	}
	st := status.Convert(err)
	if st.Code() != codes.Unauthenticated {
		t.Fatalf("unexpected code: %v", st.Code())
	}
	if st.Message() != "unauthenticated" {
		t.Fatalf("unexpected message: %q", st.Message())
	}
}

func TestLogoutHandlerEndSessionErrorNoRedirect(t *testing.T) {
	op := newFakeOP(t, "client")
	op.endURL = ":://bad-url"
	id := op.sign("user-1", time.Now().Add(time.Hour), time.Now())

	c := Config{IssuerURL: op.issuer, ClientID: "client", ClientSecret: "secret", OauthCallback: "http://app.test/auth/callback"}
	hh, err := c.WebHandler(context.Background())
	if err != nil {
		t.Fatalf("create handler: %v", err)
	}
	h := hh.(*webHandler)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "http://app.test/logout", nil)
	r.AddCookie(&http.Cookie{Name: h.cookieConfig.IDTokenName, Value: id})

	h.LogoutHandler(w, r)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}
	if got := w.Header().Get("Location"); got != "" {
		t.Fatalf("unexpected redirect location: %q", got)
	}
}

func TestDeviceRefreshRejectsMissingIDToken(t *testing.T) {
	op := newFakeOP(t, "client")
	op.includeIDToken = false

	c := Config{IssuerURL: op.issuer, ClientID: "client", ClientSecret: "secret", OauthCallback: "http://app.test/auth/callback"}
	h, err := c.DeviceHandler(context.Background())
	if err != nil {
		t.Fatalf("create device handler: %v", err)
	}

	tk := &Token{}
	tk.Subject = "user-1"
	_, _, _, err = h.Refresh(context.Background(), tk, "refresh-old")
	if err == nil {
		t.Fatal("expected refresh error when id_token is missing")
	}
	if !strings.Contains(err.Error(), "id_token not found") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDeviceLogoutUsesInputTokenWhenRefreshOmitsIDToken(t *testing.T) {
	op := newFakeOP(t, "client")
	op.includeIDToken = false
	op.requireHint = true
	raw := op.sign("user-1", time.Now().Add(time.Hour), time.Now())

	c := Config{IssuerURL: op.issuer, ClientID: "client", ClientSecret: "secret", OauthCallback: "http://app.test/auth/callback"}
	h, err := c.DeviceHandler(context.Background())
	if err != nil {
		t.Fatalf("create device handler: %v", err)
	}

	tk := &Token{}
	tk.Subject = "user-1"
	err = h.Logout(context.Background(), tk, raw, "refresh-old")
	if err != nil {
		t.Fatalf("device logout failed: %v (hint=%q)", err, op.lastHint)
	}
}
