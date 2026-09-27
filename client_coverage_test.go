package deviceauth

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

func TestNewClientValidation(t *testing.T) {
	for name, cfg := range map[string]ClientConfig{
		"empty issuer": {
			Issuer:   "",
			ClientID: "client1",
		},
		"relative issuer": {
			Issuer:   "/auth",
			ClientID: "client1",
		},
		"issuer with userinfo": {
			Issuer:   "https://user:pass@example.com",
			ClientID: "client1",
		},
		"issuer with query": {
			Issuer:   "https://example.com?query=1",
			ClientID: "client1",
		},
		"issuer with fragment": {
			Issuer:   "https://example.com#fragment",
			ClientID: "client1",
		},
		"issuer with encoded path": {
			Issuer:   "https://example.com/a%20b",
			ClientID: "client1",
		},
		"http non-loopback": {
			Issuer:   "http://example.com",
			ClientID: "client1",
		},
		"empty client ID": {
			Issuer:   "https://example.com",
			ClientID: "",
		},
		"required scopes missing from requested": {
			Issuer:         "https://example.com",
			ClientID:       "client1",
			Scopes:         []string{"read"},
			RequiredScopes: []string{"read", "write"},
		},
		"empty scopes": {
			Issuer:   "https://example.com",
			ClientID: "client1",
			Scopes:   []string{},
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := NewClient(cfg)
			if err == nil {
				t.Fatalf("expected error for %s", name)
			}
		})
	}

	// Valid IPv6 and loopback formats
	for _, rawIssuer := range []string{
		"http://localhost:8080",
		"http://foo.localhost",
		"http://127.0.0.1:8080",
		"http://[::1]:8080",
		"https://example.com:443/",
		"http://127.0.0.1:80/",
	} {
		client, err := NewClient(ClientConfig{
			Issuer:   rawIssuer,
			ClientID: "client1",
			Scopes:   []string{"read"},
		})
		if err != nil {
			t.Errorf("expected success for %s, got: %v", rawIssuer, err)
		} else if client == nil {
			t.Errorf("expected client for %s", rawIssuer)
		}
	}
}

func TestUserInfoEdgeCases(t *testing.T) {
	client := newTestClient(t, "https://example.com", "test-client")
	ctx := context.Background()

	// Nil token
	if _, err := client.UserInfo(ctx, nil); err == nil {
		t.Error("expected error for nil token")
	}

	// Empty access token
	if _, err := client.UserInfo(ctx, &oauth2.Token{AccessToken: ""}); err == nil {
		t.Error("expected error for empty access token")
	}

	// Server returning 401
	s401 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"invalid_token"}`, http.StatusUnauthorized)
	}))
	defer s401.Close()

	c401 := newTestClient(t, s401.URL, "test-client")
	if _, err := c401.UserInfo(ctx, &oauth2.Token{AccessToken: "token"}); err == nil {
		t.Error("expected error for 401 response")
	}

	// Server returning malformed json
	sCorrupt := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("not json"))
	}))
	defer sCorrupt.Close()

	cCorrupt := newTestClient(t, sCorrupt.URL, "test-client")
	if _, err := cCorrupt.UserInfo(ctx, &oauth2.Token{AccessToken: "token"}); err == nil {
		t.Error("expected error for corrupt response")
	}

	// Server with missing subject
	sNoSub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, map[string]any{"sub": "", "aud": "test-client"})
	}))
	defer sNoSub.Close()

	cNoSub := newTestClient(t, sNoSub.URL, "test-client")
	if _, err := cNoSub.UserInfo(ctx, &oauth2.Token{AccessToken: "token"}); err == nil {
		t.Error("expected error for empty subject")
	}

	// Server with invalid audience type
	sBadAud := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, map[string]any{"sub": "sub1", "aud": 123})
	}))
	defer sBadAud.Close()

	cBadAud := newTestClient(t, sBadAud.URL, "test-client")
	if _, err := cBadAud.UserInfo(ctx, &oauth2.Token{AccessToken: "token"}); err == nil {
		t.Error("expected error for bad audience type")
	}

	// Server with mismatched audience
	sWrongAud := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, map[string]any{"sub": "sub1", "aud": "other-client"})
	}))
	defer sWrongAud.Close()

	cWrongAud := newTestClient(t, sWrongAud.URL, "test-client")
	if _, err := cWrongAud.UserInfo(ctx, &oauth2.Token{AccessToken: "token"}); err == nil {
		t.Error("expected error for wrong audience")
	}

	// Server with invalid scope type
	sBadScope := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, map[string]any{"sub": "sub1", "aud": "test-client", "scope": 123})
	}))
	defer sBadScope.Close()

	cBadScope := newTestClient(t, sBadScope.URL, "test-client")
	if _, err := cBadScope.UserInfo(ctx, &oauth2.Token{AccessToken: "token"}); err == nil {
		t.Error("expected error for bad scope type")
	}
}

func TestDeviceLoginAndStoreEdgeCases(t *testing.T) {
	client := newTestClient(t, "https://example.com", "test-client")
	ctx := context.Background()

	// Nil store
	if _, err := client.DeviceLoginAndStore(ctx, DeviceLoginOptions{}, nil); err == nil {
		t.Error("expected error for nil store")
	}

	// Store load failure
	badStore := &memoryStore{loadErr: errors.New("load failed")}
	if _, err := client.DeviceLoginAndStore(ctx, DeviceLoginOptions{}, badStore); err == nil {
		t.Error("expected error for store load failure")
	}

	// DeviceLogin failure
	goodStore := &memoryStore{}
	if _, err := client.DeviceLoginAndStore(ctx, DeviceLoginOptions{}, goodStore); err == nil {
		t.Error("expected error when options are empty/invalid")
	}

	// Transformer returns error or empty access token
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/device/code":
			writeJSON(t, w, map[string]any{
				"device_code":      "device-secret",
				"user_code":        "ABCD-EFGH",
				"verification_uri": server.URL + "/verify",
				"expires_in":       600,
			})
		case "/oauth/token":
			writeJSON(t, w, map[string]any{
				"access_token": "token1",
				"token_type":   "Bearer",
			})
		case "/oauth/revoke":
			writeJSON(t, w, map[string]any{})
		case "/oauth/userinfo":
			writeJSON(t, w, map[string]any{
				"sub":   "user1",
				"aud":   "test-client",
				"scope": "read",
			})
		}
	}))
	defer server.Close()

	c := newTestClient(t, server.URL, "test-client")
	c.requiredScopes = []string{"read", "admin"}

	// Transformer returns error
	_, err := c.DeviceLoginAndStore(ctx, DeviceLoginOptions{
		Output:      &bytes.Buffer{},
		ErrorOutput: &bytes.Buffer{},
		TokenTransformer: func(_ context.Context, _ *oauth2.Token) (*oauth2.Token, error) {
			return nil, errors.New("transform err")
		},
	}, goodStore)
	if err == nil || !strings.Contains(err.Error(), "transform err") {
		t.Fatalf("expected transform err, got: %v", err)
	}

	// Transformer returns empty token
	_, err = c.DeviceLoginAndStore(ctx, DeviceLoginOptions{
		Output:      &bytes.Buffer{},
		ErrorOutput: &bytes.Buffer{},
		TokenTransformer: func(_ context.Context, _ *oauth2.Token) (*oauth2.Token, error) {
			return &oauth2.Token{AccessToken: ""}, nil
		},
	}, goodStore)
	if err == nil || !strings.Contains(err.Error(), "empty access token") {
		t.Fatalf("expected empty access token error, got: %v", err)
	}

	// Required scopes not granted
	_, err = c.DeviceLoginAndStore(ctx, DeviceLoginOptions{
		Output:      &bytes.Buffer{},
		ErrorOutput: &bytes.Buffer{},
	}, goodStore)
	if err == nil || !strings.Contains(err.Error(), "required scope") {
		t.Fatalf("expected required scope error, got: %v", err)
	}

	// Store save error
	cNoRequired := newTestClient(t, server.URL, "test-client")
	saveFailStore := &memoryStore{saveErr: errors.New("disk full")}
	_, err = cNoRequired.DeviceLoginAndStore(ctx, DeviceLoginOptions{
		Output:      &bytes.Buffer{},
		ErrorOutput: &bytes.Buffer{},
	}, saveFailStore)
	if err == nil || !strings.Contains(err.Error(), "disk full") {
		t.Fatalf("expected save error, got: %v", err)
	}
}

func TestRevocationWarningAndUnwrap(t *testing.T) {
	warn := &ReplacementRevocationWarning{Cause: errors.New("revoke failed")}
	if !strings.Contains(warn.Error(), "previous credential could not be revoked") {
		t.Errorf("unexpected error message: %s", warn.Error())
	}
	if warn.Unwrap() == nil || warn.Unwrap().Error() != "revoke failed" {
		t.Errorf("unexpected unwrap: %v", warn.Unwrap())
	}
}

func TestLogoutEdgeCases(t *testing.T) {
	ctx := context.Background()

	// Nil store
	c := newTestClient(t, "https://example.com", "test-client")
	if err := c.Logout(ctx, nil); err == nil {
		t.Error("expected error for nil store")
	}

	// ErrCredentialNotFound succeeds
	emptyStore := &memoryStore{}
	if err := c.Logout(ctx, emptyStore); err != nil {
		t.Errorf("expected nil error on empty store, got: %v", err)
	}

	// Load error other than not found
	errStore := &memoryStore{loadErr: errors.New("load failed")}
	if err := c.Logout(ctx, errStore); err == nil {
		t.Error("expected error for load failure")
	}

	// Server where revoke fails
	sRevokeFail := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "revoke error", http.StatusInternalServerError)
	}))
	defer sRevokeFail.Close()

	cRevokeFail := newTestClient(t, sRevokeFail.URL, "test-client")
	validStore := &memoryStore{
		credential: Credential{
			Issuer:      sRevokeFail.URL,
			ClientID:    "test-client",
			AccessToken: "token123",
		},
	}
	if err := cRevokeFail.Logout(ctx, validStore); err == nil {
		t.Error("expected error when revoke fails")
	}

	// Server where revoke succeeds but delete fails
	sRevokeOk := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, map[string]any{})
	}))
	defer sRevokeOk.Close()

	cRevokeOk := newTestClient(t, sRevokeOk.URL, "test-client")
	deleteFailStore := &memoryStore{
		credential: Credential{
			Issuer:      sRevokeOk.URL,
			ClientID:    "test-client",
			AccessToken: "token123",
		},
		deleteErr: errors.New("delete failed"),
	}
	if err := cRevokeOk.Logout(ctx, deleteFailStore); err == nil {
		t.Error("expected error when delete fails")
	}
}

func TestRevokeEdgeCases(t *testing.T) {
	c := newTestClient(t, "https://example.com", "test-client")
	ctx := context.Background()

	// Empty token
	if err := c.Revoke(ctx, ""); err == nil {
		t.Error("expected error for empty token")
	}

	// Cancelled context
	cancelCtx, cancel := context.WithCancel(ctx)
	cancel()
	if err := c.Revoke(cancelCtx, "token"); err == nil {
		t.Error("expected error on cancelled context")
	}
}

func TestNewKeyringStoreOnClient(t *testing.T) {
	origBackend := defaultKeyringBackend
	defer func() { defaultKeyringBackend = origBackend }()
	fake := &fakeCredentialKeyring{values: make(map[string]string)}
	defaultKeyringBackend = fake

	// Missing keyring config
	cNoKeyring := newTestClient(t, "https://example.com", "test-client")
	if _, err := cNoKeyring.NewKeyringStore(); err == nil {
		t.Error("expected error when keyring service/account missing")
	}

	// Valid keyring config
	cWithKeyring, err := NewClient(ClientConfig{
		Issuer:         "https://example.com",
		ClientID:       "test-client",
		Scopes:         []string{"read"},
		KeyringService: "my-service",
		KeyringAccount: "my-account",
	})
	if err != nil {
		t.Fatal(err)
	}
	store, err := cWithKeyring.NewKeyringStore()
	if err != nil {
		t.Fatalf("expected NewKeyringStore success, got: %v", err)
	}
	if err := store.Delete(); err != nil {
		t.Errorf("Delete error = %v", err)
	}
}

func TestHelpers(t *testing.T) {
	// redactTokens
	if err := redactTokens(nil, map[string]struct{}{"tok": {}}); err != nil {
		t.Error("expected nil for nil err")
	}
	if err := redactTokens(errors.New("err"), nil); err == nil || err.Error() != "err" {
		t.Error("expected original error for empty set")
	}
	redacted := redactTokens(errors.New("bad tok error"), map[string]struct{}{"tok": {}})
	if redacted.Error() != "bad [redacted] error" {
		t.Errorf("got %q, want 'bad [redacted] error'", redacted.Error())
	}
	if unwrap, ok := redacted.(interface{ Unwrap() error }); ok {
		if unwrap.Unwrap().Error() != "bad tok error" {
			t.Errorf("unexpected unwrap: %v", unwrap.Unwrap())
		}
	}

	// isLoopbackHost
	if !isLoopbackHost("localhost") {
		t.Error("localhost should be loopback")
	}
	if !isLoopbackHost("sub.localhost") {
		t.Error("sub.localhost should be loopback")
	}
	if isLoopbackHost("example.com") {
		t.Error("example.com should not be loopback")
	}

	// decodeStringOrArray
	if res, err := decodeStringOrArray(nil, "f", true); err != nil || res != nil {
		t.Errorf("unexpected: %v, %v", res, err)
	}
	if _, err := decodeStringOrArray(nil, "f", false); err == nil {
		t.Error("expected error for non-optional nil")
	}
	if _, err := decodeStringOrArray([]byte(`""`), "f", false); err == nil {
		t.Error("expected error for non-optional empty string")
	}
	if _, err := decodeStringOrArray([]byte(`[]`), "f", false); err == nil {
		t.Error("expected error for non-optional empty array")
	}

	// compactStrings
	compacted := compactStrings([]string{"a", "", "b", "a", "  "})
	if len(compacted) != 2 || compacted[0] != "a" || compacted[1] != "b" {
		t.Errorf("unexpected compactStrings: %v", compacted)
	}

	// httpClient with custom client in ctx
	customClient := &http.Client{Timeout: 42 * time.Second}
	ctxWithClient := context.WithValue(context.Background(), oauth2.HTTPClient, customClient)
	if got := httpClient(ctxWithClient); got != customClient {
		t.Errorf("expected custom client, got: %v", got)
	}

	// ResponseError
	reNoOAuth := &ResponseError{Operation: "userinfo", StatusCode: 500}
	if !strings.Contains(reNoOAuth.Error(), "HTTP 500") || strings.Contains(reNoOAuth.Error(), "(") {
		t.Errorf("unexpected format: %s", reNoOAuth.Error())
	}
	reWithOAuth := &ResponseError{Operation: "revoke", StatusCode: 400, OAuthError: "invalid_request"}
	if !strings.Contains(reWithOAuth.Error(), "(invalid_request)") {
		t.Errorf("unexpected format: %s", reWithOAuth.Error())
	}

	// safeOAuthErrorCode
	if safeOAuthErrorCode("unknown_error") != "" {
		t.Error("expected empty string for unknown error")
	}
	if safeOAuthErrorCode("invalid_request") != "invalid_request" {
		t.Error("expected invalid_request")
	}
}

func TestClientAdditionalCoverage(t *testing.T) {
	ctx := context.Background()

	// Line 151 & 416: invalid URL endpoint causes http.NewRequestWithContext to fail
	cBad := &Client{
		issuer:   &url.URL{Scheme: "http", Host: "invalid host with spaces\x7f"},
		clientID: "test-client",
	}
	if _, err := cBad.UserInfo(ctx, &oauth2.Token{AccessToken: "tok"}); err == nil {
		t.Error("expected error from bad endpoint in UserInfo")
	}
	if err := cBad.Revoke(ctx, "tok"); err == nil {
		t.Error("expected error from bad endpoint in Revoke")
	}

	// Line 161: Do error in UserInfo
	sTimeout := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	sTimeout.Close() // immediately closed so Do fails
	cTimeout := newTestClient(t, sTimeout.URL, "test-client")
	if _, err := cTimeout.UserInfo(ctx, &oauth2.Token{AccessToken: "tok"}); err == nil {
		t.Error("expected error from closed server in UserInfo")
	}

	// Line 256: UserInfo error during DeviceLoginAndStore
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/device/code":
			writeJSON(t, w, map[string]any{
				"device_code":      "device-secret",
				"user_code":        "ABCD-EFGH",
				"verification_uri": server.URL + "/verify",
				"expires_in":       600,
			})
		case "/oauth/token":
			writeJSON(t, w, map[string]any{
				"access_token": "token1",
				"token_type":   "Bearer",
			})
		case "/oauth/revoke":
			writeJSON(t, w, map[string]any{})
		case "/oauth/userinfo":
			http.Error(w, "bad userinfo", http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	cServer := newTestClient(t, server.URL, "test-client")
	_, err := cServer.DeviceLoginAndStore(ctx, DeviceLoginOptions{
		Output:      &bytes.Buffer{},
		ErrorOutput: &bytes.Buffer{},
	}, &memoryStore{})
	if err == nil || !strings.Contains(err.Error(), "userinfo") {
		t.Fatalf("expected userinfo failure, got: %v", err)
	}

	// Lines 316, 323, 330: withTokenCleanup with nil token and failing revoke
	sRevokeFail := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "fail", http.StatusInternalServerError)
	}))
	defer sRevokeFail.Close()

	cRevFail := newTestClient(t, sRevokeFail.URL, "test-client")
	cleanupErr := cRevFail.withTokenCleanup(ctx, errors.New("primary error"), nil, &oauth2.Token{AccessToken: ""}, &oauth2.Token{AccessToken: "tok1"})
	if cleanupErr == nil || !strings.Contains(cleanupErr.Error(), "revoke incomplete device login") {
		t.Fatalf("expected cleanup error, got: %v", cleanupErr)
	}

	// Lines 379-380: NewKeyringStore fails when defaultKeyringBackend is nil
	origBackend := defaultKeyringBackend
	defer func() { defaultKeyringBackend = origBackend }()
	defaultKeyringBackend = nil

	cKeyringFail, _ := NewClient(ClientConfig{
		Issuer:         "https://example.com",
		ClientID:       "test-client",
		Scopes:         []string{"read"},
		KeyringService: "svc",
		KeyringAccount: "acc",
	})
	if _, err := cKeyringFail.NewKeyringStore(); err == nil {
		t.Error("expected NewKeyringStore to fail when backend is nil")
	}

	// Line 493: parseIssuer with empty hostname
	if _, err := parseIssuer("https://:8080"); err == nil {
		t.Error("expected error for empty hostname")
	}

	// Line 504: parseIssuer with IPv6 port 80/443
	if _, err := parseIssuer("http://[::1]:80"); err != nil {
		t.Errorf("expected success for IPv6 with standard port, got: %v", err)
	}
}
