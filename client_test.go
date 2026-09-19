package deviceauth

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
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
	err        error
}

func (s *memoryStore) Save(credential Credential) error {
	if s.err != nil {
		return s.err
	}
	s.credential = credential
	s.deleted = false
	return nil
}

func (s *memoryStore) Load() (Credential, error) {
	if s.err != nil {
		return Credential{}, s.err
	}
	if s.deleted || s.credential.AccessToken == "" {
		return Credential{}, ErrCredentialNotFound
	}
	return s.credential, nil
}

func (s *memoryStore) Delete() error {
	if s.err != nil {
		return s.err
	}
	s.deleted = true
	return nil
}

var _ Store = (*memoryStore)(nil)
