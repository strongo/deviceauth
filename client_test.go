package deviceauth

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"golang.org/x/oauth2"
)

func TestClientDeviceLoginAndStore(t *testing.T) {
	t.Parallel()

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/device/code":
			if got := r.FormValue("client_id"); got != "sneat-cli" {
				t.Fatalf("client_id = %q", got)
			}
			if got := r.FormValue("scope"); got != "spaces:read profile:read" {
				t.Fatalf("scope = %q", got)
			}
			writeJSON(t, w, map[string]any{
				"device_code":      "device-secret",
				"user_code":        "ABCD-EFGH",
				"verification_uri": server.URL + "/device",
				"expires_in":       600,
				"interval":         1,
			})
		case "/oauth/token":
			if got := r.FormValue("client_id"); got != "sneat-cli" {
				t.Fatalf("token client_id = %q", got)
			}
			if got := r.Header.Get("Authorization"); got != "" {
				t.Fatalf("token Authorization = %q, want empty for AuthStyleInParams", got)
			}
			writeJSON(t, w, map[string]any{
				"access_token":  "access-secret",
				"refresh_token": "refresh-secret",
				"token_type":    "urn:ietf:params:oauth:token-type:firebase-custom-token",
				"expires_in":    3600,
			})
		case "/oauth/userinfo":
			if got := r.Header.Get("Authorization"); got != "Bearer firebase-id-token" {
				t.Fatalf("Authorization = %q", got)
			}
			writeJSON(t, w, map[string]any{
				"sub":   "firebase-user-id",
				"name":  "Alex Example",
				"email": "alex@example.test",
				"aud":   []string{"web-client", "sneat-cli"},
				"scope": "spaces:read profile:read",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := newTestClient(t, server.URL, "sneat-cli")
	store := &memoryStore{}
	result, err := client.DeviceLoginAndStore(context.Background(), DeviceLoginOptions{
		DeviceInfo:  DeviceInfo{Name: "test device"},
		Output:      &bytes.Buffer{},
		ErrorOutput: &bytes.Buffer{},
		TokenTransformer: func(_ context.Context, deviceToken *oauth2.Token) (*oauth2.Token, error) {
			if deviceToken.AccessToken != "access-secret" {
				t.Fatalf("device access token = %q", deviceToken.AccessToken)
			}
			if deviceToken.TokenType != "urn:ietf:params:oauth:token-type:firebase-custom-token" {
				t.Fatalf("device token type = %q", deviceToken.TokenType)
			}
			return &oauth2.Token{AccessToken: "firebase-id-token", RefreshToken: "firebase-refresh-token", TokenType: "Bearer"}, nil
		},
	}, store)
	if err != nil {
		t.Fatalf("DeviceLoginAndStore() error = %v", err)
	}
	if result.Identity.Subject != "firebase-user-id" {
		t.Fatalf("subject = %q", result.Identity.Subject)
	}
	if result.Credential.Issuer != server.URL || result.Credential.ClientID != "sneat-cli" {
		t.Fatalf("credential binding = %#v", result.Credential)
	}
	if result.Credential.AccountName != "Alex Example" {
		t.Fatalf("account name = %q", result.Credential.AccountName)
	}
	loaded, err := client.ScopedStore(store).Load()
	if err != nil {
		t.Fatalf("load saved credential: %v", err)
	}
	if loaded.AccessToken != "firebase-id-token" || loaded.RefreshToken != "firebase-refresh-token" {
		t.Fatalf("credential = %#v", loaded)
	}
	if result.Login.Token.AccessToken != "access-secret" || result.SessionToken.AccessToken != "firebase-id-token" {
		t.Fatalf("device/session tokens = %#v / %#v", result.Login.Token, result.SessionToken)
	}
}

func TestClientUserInfoRequiresMatchingAudience(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, map[string]any{"sub": "user-1", "aud": "datatug-cli"})
	}))
	defer server.Close()
	client := newTestClient(t, server.URL, "sneat-cli")
	_, err := client.UserInfo(context.Background(), &oauth2.Token{AccessToken: "access-secret"})
	if err == nil || !strings.Contains(err.Error(), "audience") {
		t.Fatalf("UserInfo() error = %v", err)
	}
}

func TestClientScopedStoreRejectsOtherIssuerOrClient(t *testing.T) {
	t.Parallel()

	client := newTestClient(t, "https://auth.sneat.co", "sneat-cli")
	store := &memoryStore{credential: Credential{
		AccessToken: "access-secret",
		Issuer:      "https://auth.sneat.co",
		ClientID:    "datatug-cli",
	}}
	_, err := client.ScopedStore(store).Load()
	if !errors.Is(err, ErrCredentialScopeMismatch) {
		t.Fatalf("Load() error = %v", err)
	}
	if err := client.ScopedStore(store).Save(Credential{AccessToken: "wrong-token", ClientID: "datatug-cli"}); !errors.Is(err, ErrCredentialScopeMismatch) {
		t.Fatalf("Save() error = %v", err)
	}
	if err := client.ScopedStore(store).Save(Credential{AccessToken: "new-token"}); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	if store.credential.Issuer != "https://auth.sneat.co" || store.credential.ClientID != "sneat-cli" {
		t.Fatalf("stored credential = %#v", store.credential)
	}
}

func TestClientLogoutRevokesThenDeletes(t *testing.T) {
	t.Parallel()

	var revoked string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth/revoke" {
			http.NotFound(w, r)
			return
		}
		revoked = r.FormValue("token")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	client := newTestClient(t, server.URL, "datatug-cli")
	store := &memoryStore{credential: Credential{
		AccessToken: "access-secret",
		Issuer:      server.URL,
		ClientID:    "datatug-cli",
	}}
	if err := client.Logout(context.Background(), store); err != nil {
		t.Fatalf("Logout() error = %v", err)
	}
	if revoked != "access-secret" {
		t.Fatalf("revoked token = %q", revoked)
	}
	if !store.deleted {
		t.Fatal("credential was not deleted")
	}
}

func TestClientLogoutKeepsCredentialWhenRevokeFails(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "temporary outage", http.StatusServiceUnavailable)
	}))
	defer server.Close()
	client := newTestClient(t, server.URL, "datatug-cli")
	store := &memoryStore{credential: Credential{
		AccessToken: "access-secret",
		Issuer:      server.URL,
		ClientID:    "datatug-cli",
	}}
	if err := client.Logout(context.Background(), store); err == nil {
		t.Fatal("Logout() error = nil")
	}
	if store.deleted {
		t.Fatal("credential was deleted after failed revoke")
	}
}

func TestNewClientValidatesConfigAndBuildsEndpoints(t *testing.T) {
	t.Parallel()

	if _, err := NewClient(ClientConfig{Issuer: "https://auth.sneat.co"}); err == nil {
		t.Fatal("NewClient() error = nil")
	}
	if _, err := NewClient(ClientConfig{Issuer: "https://auth.sneat.co?bad=1", ClientID: "cli", Scopes: []string{"profile:read"}}); err == nil {
		t.Fatal("NewClient() accepted issuer query")
	}
	client := newTestClient(t, "https://auth.sneat.co/base/", "sneat-cli")
	config := client.OAuthConfig()
	if config.Endpoint.DeviceAuthURL != "https://auth.sneat.co/base/oauth/device/code" || config.Endpoint.TokenURL != "https://auth.sneat.co/base/oauth/token" {
		t.Fatalf("endpoints = %#v", config.Endpoint)
	}
}

func TestNewClientCanonicalizesAndRestrictsIssuer(t *testing.T) {
	t.Parallel()

	client := newTestClient(t, "HTTPS://AUTH.SNEAT.CO:443/base/", "sneat-cli")
	if got, want := client.Issuer(), "https://auth.sneat.co/base"; got != want {
		t.Fatalf("Issuer() = %q, want %q", got, want)
	}
	for _, issuer := range []string{
		"http://auth.sneat.co",
		"https://alex@auth.sneat.co",
		"https://auth.sneat.co/base%2fadmin",
	} {
		if _, err := NewClient(ClientConfig{Issuer: issuer, ClientID: "cli", Scopes: []string{"profile:read"}}); err == nil {
			t.Fatalf("NewClient(%q) error = nil", issuer)
		}
	}
	if _, err := NewClient(ClientConfig{Issuer: "http://127.0.0.1:8080", ClientID: "cli", Scopes: []string{"profile:read"}}); err != nil {
		t.Fatalf("NewClient() rejected loopback HTTP: %v", err)
	}
}

func TestClientDeviceLoginPollsAuthorizationPending(t *testing.T) {
	var tokenRequests atomic.Int32
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/device/code":
			writeJSON(t, w, map[string]any{
				"device_code":      "device-secret",
				"user_code":        "ABCD-EFGH",
				"verification_uri": server.URL + "/device",
				"expires_in":       600,
				"interval":         1,
			})
		case "/oauth/token":
			if got := r.FormValue("client_id"); got != "sneat-cli" {
				t.Fatalf("token client_id = %q", got)
			}
			if tokenRequests.Add(1) == 1 {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				writeJSON(t, w, map[string]string{"error": "authorization_pending"})
				return
			}
			writeJSON(t, w, map[string]string{"access_token": "access-secret", "token_type": "Bearer"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := newTestClient(t, server.URL, "sneat-cli")
	result, err := client.DeviceLogin(context.Background(), DeviceLoginOptions{Output: &bytes.Buffer{}, ErrorOutput: &bytes.Buffer{}})
	if err != nil {
		t.Fatalf("DeviceLogin() error = %v", err)
	}
	if result.Token.AccessToken != "access-secret" {
		t.Fatalf("access token = %q", result.Token.AccessToken)
	}
	if got := tokenRequests.Load(); got != 2 {
		t.Fatalf("token request count = %d, want 2", got)
	}
}

func TestClientDeviceLoginAndStoreRevokesTokensAfterStoreFailure(t *testing.T) {
	var revoked []string
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/device/code":
			writeJSON(t, w, map[string]any{"device_code": "device-secret", "user_code": "ABCD", "verification_uri": server.URL + "/device", "expires_in": 600, "interval": 1})
		case "/oauth/token":
			writeJSON(t, w, map[string]string{"access_token": "bootstrap-token", "token_type": "custom"})
		case "/oauth/userinfo":
			writeJSON(t, w, map[string]any{"sub": "user-1", "aud": "sneat-cli", "scope": "profile:read"})
		case "/oauth/revoke":
			revoked = append(revoked, r.FormValue("token"))
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := newTestClient(t, server.URL, "sneat-cli")
	store := &memoryStore{saveErr: errors.New("credential store unavailable")}
	_, err := client.DeviceLoginAndStore(context.Background(), DeviceLoginOptions{
		Output:      &bytes.Buffer{},
		ErrorOutput: &bytes.Buffer{},
		TokenTransformer: func(context.Context, *oauth2.Token) (*oauth2.Token, error) {
			return &oauth2.Token{AccessToken: "session-token", TokenType: "Bearer"}, nil
		},
	}, store)
	if err == nil || !strings.Contains(err.Error(), "save device credential") {
		t.Fatalf("DeviceLoginAndStore() error = %v", err)
	}
	if got := strings.Join(revoked, ","); got != "bootstrap-token,session-token" {
		t.Fatalf("revoked = %q", got)
	}
}

func TestValidateRequiredScopes(t *testing.T) {
	t.Parallel()

	if err := ValidateRequiredScopes(nil, []string{"spaces:write"}); err == nil {
		t.Fatal("ValidateRequiredScopes() error = nil")
	}
	if err := ValidateRequiredScopes([]string{"spaces:read"}, []string{"spaces:read"}); err != nil {
		t.Fatalf("ValidateRequiredScopes() error = %v", err)
	}
	if _, err := NewClient(ClientConfig{Issuer: "https://auth.sneat.co", ClientID: "cli", Scopes: []string{"profile:read"}, RequiredScopes: []string{"spaces:read"}}); err == nil {
		t.Fatal("NewClient() accepted an unrequested required scope")
	}
}

func TestClientDeviceLoginAndStoreRevokesBootstrapAfterTransformFailure(t *testing.T) {
	var revoked string
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/device/code":
			writeJSON(t, w, map[string]any{"device_code": "device-secret", "user_code": "ABCD", "verification_uri": server.URL + "/device", "expires_in": 600, "interval": 1})
		case "/oauth/token":
			writeJSON(t, w, map[string]string{"access_token": "bootstrap-token", "token_type": "custom"})
		case "/oauth/revoke":
			revoked = r.FormValue("token")
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := newTestClient(t, server.URL, "sneat-cli")
	_, err := client.DeviceLoginAndStore(context.Background(), DeviceLoginOptions{
		Output:      &bytes.Buffer{},
		ErrorOutput: &bytes.Buffer{},
		TokenTransformer: func(_ context.Context, token *oauth2.Token) (*oauth2.Token, error) {
			return nil, fmt.Errorf("session exchange rejected %s", token.AccessToken)
		},
	}, &memoryStore{})
	if err == nil || !strings.Contains(err.Error(), "transform device token") {
		t.Fatalf("DeviceLoginAndStore() error = %v", err)
	}
	if strings.Contains(err.Error(), "bootstrap-token") {
		t.Fatalf("DeviceLoginAndStore() leaked bootstrap token: %v", err)
	}
	if revoked != "bootstrap-token" {
		t.Fatalf("revoked token = %q", revoked)
	}
}

func TestClientDeviceLoginAndStoreRevokesReplacedCredential(t *testing.T) {
	var revoked string
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/device/code":
			writeJSON(t, w, map[string]any{"device_code": "device-secret", "user_code": "ABCD", "verification_uri": server.URL + "/device", "expires_in": 600, "interval": 1})
		case "/oauth/token":
			writeJSON(t, w, map[string]string{"access_token": "new-token", "token_type": "Bearer"})
		case "/oauth/userinfo":
			writeJSON(t, w, map[string]any{"sub": "user-1", "aud": "sneat-cli", "scope": "profile:read"})
		case "/oauth/revoke":
			revoked = r.FormValue("token")
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := newTestClient(t, server.URL, "sneat-cli")
	store := &memoryStore{credential: Credential{AccessToken: "old-token", Issuer: server.URL, ClientID: "sneat-cli"}}
	result, err := client.DeviceLoginAndStore(context.Background(), DeviceLoginOptions{Output: &bytes.Buffer{}, ErrorOutput: &bytes.Buffer{}}, store)
	if err != nil {
		t.Fatalf("DeviceLoginAndStore() error = %v", err)
	}
	if result.Credential.AccessToken != "new-token" || store.credential.AccessToken != "new-token" {
		t.Fatalf("credential = %#v, store = %#v", result.Credential, store.credential)
	}
	if revoked != "old-token" {
		t.Fatalf("revoked token = %q", revoked)
	}
}

func TestClientDeviceLoginAndStoreWarnsWhenReplacedCredentialCannotBeRevoked(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/device/code":
			writeJSON(t, w, map[string]any{"device_code": "device-secret", "user_code": "ABCD", "verification_uri": server.URL + "/device", "expires_in": 600, "interval": 1})
		case "/oauth/token":
			writeJSON(t, w, map[string]string{"access_token": "new-token", "token_type": "Bearer"})
		case "/oauth/userinfo":
			writeJSON(t, w, map[string]any{"sub": "user-1", "aud": "sneat-cli", "scope": "profile:read"})
		case "/oauth/revoke":
			http.Error(w, "upstream unavailable", http.StatusServiceUnavailable)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := newTestClient(t, server.URL, "sneat-cli")
	store := &memoryStore{credential: Credential{AccessToken: "old-token", Issuer: server.URL, ClientID: "sneat-cli"}}
	result, err := client.DeviceLoginAndStore(context.Background(), DeviceLoginOptions{Output: &bytes.Buffer{}, ErrorOutput: &bytes.Buffer{}}, store)
	if err != nil {
		t.Fatalf("DeviceLoginAndStore() error = %v", err)
	}
	if result.Credential.AccessToken != "new-token" || store.credential.AccessToken != "new-token" {
		t.Fatalf("credential = %#v, store = %#v", result.Credential, store.credential)
	}
	if len(result.Warnings) != 1 {
		t.Fatalf("warnings = %#v", result.Warnings)
	}
	var warning *ReplacementRevocationWarning
	if !errors.As(result.Warnings[0], &warning) {
		t.Fatalf("warning = %T", result.Warnings[0])
	}
}

func TestClientDeviceLoginAndStoreCleansUpAfterCallerCancellation(t *testing.T) {
	var revoked string
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/device/code":
			writeJSON(t, w, map[string]any{"device_code": "device-secret", "user_code": "ABCD", "verification_uri": server.URL + "/device", "expires_in": 600, "interval": 1})
		case "/oauth/token":
			writeJSON(t, w, map[string]string{"access_token": "bootstrap-token", "token_type": "custom"})
		case "/oauth/revoke":
			revoked = r.FormValue("token")
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client := newTestClient(t, server.URL, "sneat-cli")
	_, err := client.DeviceLoginAndStore(ctx, DeviceLoginOptions{
		Output:      &bytes.Buffer{},
		ErrorOutput: &bytes.Buffer{},
		TokenTransformer: func(_ context.Context, token *oauth2.Token) (*oauth2.Token, error) {
			cancel()
			return nil, fmt.Errorf("exchange rejected %s", token.AccessToken)
		},
	}, &memoryStore{})
	if err == nil || strings.Contains(err.Error(), "bootstrap-token") {
		t.Fatalf("DeviceLoginAndStore() error = %v", err)
	}
	if revoked != "bootstrap-token" {
		t.Fatalf("revoked token = %q", revoked)
	}
}

func TestClientRevokeRedactsResponseBody(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(`{"error":"access-secret","error_description":"internal details"}`))
	}))
	defer server.Close()
	client := newTestClient(t, server.URL, "sneat-cli")
	err := client.Revoke(context.Background(), "access-secret")
	if err == nil {
		t.Fatal("Revoke() error = nil")
	}
	if strings.Contains(err.Error(), "access-secret") || strings.Contains(err.Error(), "internal details") {
		t.Fatalf("Revoke() leaked response body: %v", err)
	}
	var responseError *ResponseError
	if !errors.As(err, &responseError) || responseError.StatusCode != http.StatusBadGateway || responseError.Operation != "revoke" || responseError.OAuthError != "" {
		t.Fatalf("Revoke() error = %#v", err)
	}
}

func TestClientNewKeyringStoreRequiresConfiguredProductIdentity(t *testing.T) {
	t.Parallel()

	client := newTestClient(t, "https://auth.sneat.co", "sneat-cli")
	if _, err := client.NewKeyringStore(); err == nil {
		t.Fatal("NewKeyringStore() error = nil")
	}
}

func newTestClient(t *testing.T, issuer, clientID string) *Client {
	t.Helper()
	client, err := NewClient(ClientConfig{
		Issuer:   issuer,
		ClientID: clientID,
		Scopes:   []string{"spaces:read", "profile:read"},
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	return client
}

type memoryStore struct {
	credential Credential
	deleted    bool
	loadErr    error
	saveErr    error
	deleteErr  error
}

func (s *memoryStore) Save(credential Credential) error {
	if s.saveErr != nil {
		return s.saveErr
	}
	s.credential = credential
	s.deleted = false
	return nil
}

func (s *memoryStore) Load() (Credential, error) {
	if s.loadErr != nil {
		return Credential{}, s.loadErr
	}
	if s.deleted || s.credential.AccessToken == "" {
		return Credential{}, ErrCredentialNotFound
	}
	return s.credential, nil
}

func (s *memoryStore) Delete() error {
	if s.deleteErr != nil {
		return s.deleteErr
	}
	s.deleted = true
	return nil
}

var _ Store = (*memoryStore)(nil)
