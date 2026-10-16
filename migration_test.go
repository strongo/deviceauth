package deviceauth

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"golang.org/x/oauth2"
)

// oauthService is a local stand-in for the moved authorization service. It
// records every path it served so tests can prove where requests went.
type oauthService struct {
	t      *testing.T
	server *httptest.Server
	mu     sync.Mutex
	paths  []string
}

func newOAuthService(t *testing.T) *oauthService {
	t.Helper()
	service := &oauthService{t: t}
	service.server = httptest.NewServer(http.HandlerFunc(service.serve))
	t.Cleanup(service.server.Close)
	return service
}

func (s *oauthService) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.paths = append(s.paths, r.URL.Path)
	s.mu.Unlock()
	switch r.URL.Path {
	case "/oauth/device/code":
		writeJSON(s.t, w, map[string]any{
			"device_code": "device-secret", "user_code": "ABCD-EFGH",
			"verification_uri": s.server.URL + "/device", "expires_in": 600, "interval": 1,
		})
	case "/oauth/token":
		writeJSON(s.t, w, map[string]any{"access_token": "new-access", "token_type": "Bearer", "expires_in": 3600})
	case "/oauth/userinfo":
		writeJSON(s.t, w, map[string]any{"sub": "user-1", "email": "user@example.test", "aud": "sneat-cli", "scope": "spaces:read profile:read"})
	case "/oauth/revoke":
		w.WriteHeader(http.StatusOK)
	default:
		http.NotFound(w, r)
	}
}

func (s *oauthService) served() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.paths...)
}

// closedURL returns a loopback URL on which nothing listens, so requests to it
// fail the way a not-yet-serving host does: without any HTTP response.
func closedURL(t *testing.T) string {
	t.Helper()
	server := httptest.NewServer(http.NotFoundHandler())
	rawURL := server.URL
	server.Close()
	return rawURL
}

func notFoundServer(t *testing.T, hits *atomic.Int32) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.NotFound(w, r)
	}))
	t.Cleanup(server.Close)
	return server
}

func newMigrationClient(t *testing.T, config ClientConfig) *Client {
	t.Helper()
	if config.ClientID == "" {
		config.ClientID = "sneat-cli"
	}
	if config.Scopes == nil {
		config.Scopes = []string{"spaces:read", "profile:read"}
	}
	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	return client
}

func TestNewClientMigrationConfig(t *testing.T) {
	t.Parallel()

	if _, err := NewClient(ClientConfig{Issuer: "https://new.example", ClientID: "c", Scopes: []string{"s"}, PreviousIssuers: []string{"ftp://old.example"}}); err == nil || !strings.Contains(err.Error(), "previous issuer") {
		t.Fatalf("invalid previous issuer error = %v", err)
	}
	if _, err := NewClient(ClientConfig{Issuer: "https://new.example", ClientID: "c", Scopes: []string{"s"}, FallbackIssuers: []string{"http://old.example"}}); err == nil || !strings.Contains(err.Error(), "fallback issuer") {
		t.Fatalf("invalid fallback issuer error = %v", err)
	}
	client := newMigrationClient(t, ClientConfig{
		Issuer:          "https://new.example",
		PreviousIssuers: []string{"https://OLD.example/", " ", "https://old.example", "https://new.example"},
	})
	if got := client.PreviousIssuers(); len(got) != 1 || got[0] != "https://old.example" {
		t.Fatalf("PreviousIssuers() = %#v", got)
	}
	if client.router != nil {
		t.Fatal("router configured without fallbacks")
	}
	if got := client.ServingIssuer(); got != "https://new.example" {
		t.Fatalf("ServingIssuer() without fallbacks = %q", got)
	}
	withSelfFallback := newMigrationClient(t, ClientConfig{Issuer: "https://new.example", FallbackIssuers: []string{"https://new.example/"}})
	if withSelfFallback.router != nil {
		t.Fatal("router configured for a fallback equal to the issuer")
	}
}

func TestIssuerMovedErrorAndNotice(t *testing.T) {
	t.Parallel()

	moved := &IssuerMovedError{PreviousIssuer: "https://auth.sneat.co", Issuer: "https://oauth.sneat.co", Credential: Credential{AccessToken: "secret"}}
	if !errors.Is(moved, ErrCredentialIssuerMoved) || !errors.Is(moved, ErrCredentialScopeMismatch) || errors.Is(moved, ErrCredentialNotFound) {
		t.Fatal("IssuerMovedError Is() mismatch")
	}
	if strings.Contains(moved.Error(), "secret") || !strings.Contains(moved.Error(), "https://oauth.sneat.co") {
		t.Fatalf("Error() = %q", moved.Error())
	}
	if got := DefaultIssuerMovedNotice(moved); got != "Sign-in moved from auth.sneat.co to oauth.sneat.co; starting a fresh sign-in." {
		t.Fatalf("DefaultIssuerMovedNotice() = %q", got)
	}
	if got := hostOf("%zz"); got != "%zz" {
		t.Fatalf("hostOf(invalid) = %q", got)
	}
	if got := hostOf("relative"); got != "relative" {
		t.Fatalf("hostOf(relative) = %q", got)
	}
}

func TestScopedStoreReportsMovedIssuer(t *testing.T) {
	t.Parallel()

	client := newMigrationClient(t, ClientConfig{Issuer: "https://oauth.sneat.co", PreviousIssuers: []string{"https://auth.sneat.co"}})
	old := Credential{AccessToken: "old", Issuer: "https://auth.sneat.co", ClientID: "sneat-cli"}
	_, err := client.ScopedStore(&memoryStore{credential: old}).Load()
	var moved *IssuerMovedError
	if !errors.As(err, &moved) || moved.Credential.AccessToken != "old" || moved.PreviousIssuer != "https://auth.sneat.co" || moved.Issuer != "https://oauth.sneat.co" {
		t.Fatalf("Load() error = %v", err)
	}
	otherClient := Credential{AccessToken: "old", Issuer: "https://auth.sneat.co", ClientID: "other"}
	if _, err := client.ScopedStore(&memoryStore{credential: otherClient}).Load(); !errors.Is(err, ErrCredentialScopeMismatch) || errors.Is(err, ErrCredentialIssuerMoved) {
		t.Fatalf("other client Load() error = %v", err)
	}
	unknown := Credential{AccessToken: "old", Issuer: "https://elsewhere.example", ClientID: "sneat-cli"}
	if _, err := client.ScopedStore(&memoryStore{credential: unknown}).Load(); errors.Is(err, ErrCredentialIssuerMoved) || !errors.Is(err, ErrCredentialScopeMismatch) {
		t.Fatalf("unknown issuer Load() error = %v", err)
	}
}

func TestDeviceLoginAndStoreReplacesMovedCredential(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name, notice, want string
	}{
		{name: "default notice", want: "Sign-in moved from auth.sneat.co to 127.0.0.1"},
		{name: "custom notice", notice: "Sneat sign-in moved to oauth.sneat.co", want: "Sneat sign-in moved to oauth.sneat.co\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			service := newOAuthService(t)
			client := newMigrationClient(t, ClientConfig{Issuer: service.server.URL, PreviousIssuers: []string{"https://auth.sneat.co"}})
			store := &memoryStore{credential: Credential{AccessToken: "old-access", Issuer: "https://auth.sneat.co", ClientID: "sneat-cli"}}
			var stderr bytes.Buffer
			auth, err := client.DeviceLoginAndStore(context.Background(), DeviceLoginOptions{Output: io.Discard, ErrorOutput: &stderr, IssuerMovedNotice: tc.notice}, store)
			if err != nil {
				t.Fatalf("DeviceLoginAndStore() error = %v", err)
			}
			if !strings.Contains(stderr.String(), tc.want) || strings.Count(stderr.String(), "\n") != 1 {
				t.Fatalf("stderr = %q, want one line containing %q", stderr.String(), tc.want)
			}
			if len(auth.Warnings) != 0 {
				t.Fatalf("warnings = %v", auth.Warnings)
			}
			if store.credential.AccessToken != "new-access" || store.credential.Issuer != client.Issuer() {
				t.Fatalf("stored credential = %#v", store.credential)
			}
			served := service.served()
			if served[len(served)-1] != "/oauth/revoke" {
				t.Fatalf("old credential was not revoked at the current issuer: %v", served)
			}
		})
	}
}

func TestLogoutRevokesMovedCredentialAtCurrentIssuer(t *testing.T) {
	t.Parallel()

	service := newOAuthService(t)
	client := newMigrationClient(t, ClientConfig{Issuer: service.server.URL, PreviousIssuers: []string{"https://auth.sneat.co"}})
	store := &memoryStore{credential: Credential{AccessToken: "old-access", Issuer: "https://auth.sneat.co", ClientID: "sneat-cli"}}
	if err := client.Logout(context.Background(), store); err != nil {
		t.Fatalf("Logout() error = %v", err)
	}
	if !store.deleted {
		t.Fatal("moved credential was not deleted")
	}
	if served := service.served(); len(served) != 1 || served[0] != "/oauth/revoke" {
		t.Fatalf("served = %v", served)
	}
}

func TestMigratingStore(t *testing.T) {
	t.Parallel()

	current := &memoryStore{}
	previous := &memoryStore{credential: Credential{AccessToken: "old"}}
	broken := &memoryStore{loadErr: errors.New("keyring locked")}
	store := NewMigratingStore(current, broken, previous)

	got, err := store.Load()
	if err != nil || got.AccessToken != "old" {
		t.Fatalf("Load() from previous = %#v, %v", got, err)
	}
	if err := store.Save(Credential{AccessToken: "new"}); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	if !previous.deleted || !broken.deleted {
		t.Fatal("Save() did not remove previous credentials")
	}
	got, err = store.Load()
	if err != nil || got.AccessToken != "new" {
		t.Fatalf("Load() current = %#v, %v", got, err)
	}
	if err := store.Delete(); err != nil || !current.deleted {
		t.Fatalf("Delete() error = %v", err)
	}
	if _, err := store.Load(); !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("Load() after delete error = %v", err)
	}

	currentErr := errors.New("current broken")
	if _, err := NewMigratingStore(&memoryStore{loadErr: currentErr}, previous).Load(); !errors.Is(err, currentErr) {
		t.Fatalf("Load() current error = %v", err)
	}
	saveErr := errors.New("save broken")
	untouched := &memoryStore{credential: Credential{AccessToken: "old"}}
	if err := NewMigratingStore(&memoryStore{saveErr: saveErr}, untouched).Save(Credential{AccessToken: "new"}); !errors.Is(err, saveErr) || untouched.deleted {
		t.Fatalf("Save() error = %v, previous deleted = %v", err, untouched.deleted)
	}
	deleteErr := errors.New("delete broken")
	if err := NewMigratingStore(&memoryStore{}, &memoryStore{deleteErr: deleteErr}).Delete(); !errors.Is(err, deleteErr) {
		t.Fatalf("Delete() error = %v", err)
	}
}

func TestNewKeyringStoreFindsPreviousIssuerCredential(t *testing.T) {
	// Not parallel: mutates package-level defaultKeyringBackend seam.
	origBackend := defaultKeyringBackend
	defer func() { defaultKeyringBackend = origBackend }()
	fake := &fakeCredentialKeyring{values: make(map[string]string)}
	defaultKeyringBackend = fake

	config := ClientConfig{Issuer: "https://auth.sneat.co", KeyringService: "datatug-cli", KeyringAccount: "firebase-session"}
	oldClient := newMigrationClient(t, config)
	oldStore, err := oldClient.NewKeyringStore()
	if err != nil {
		t.Fatal(err)
	}
	if err := oldStore.Save(Credential{AccessToken: "old-access"}); err != nil {
		t.Fatal(err)
	}

	config.Issuer = "https://oauth.sneat.co"
	config.PreviousIssuers = []string{"https://auth.sneat.co"}
	newClient := newMigrationClient(t, config)
	store, err := newClient.NewKeyringStore()
	if err != nil {
		t.Fatal(err)
	}
	var moved *IssuerMovedError
	if _, err := store.Load(); !errors.As(err, &moved) || moved.Credential.AccessToken != "old-access" {
		t.Fatalf("Load() error = %v", err)
	}
	if err := store.Save(Credential{AccessToken: "new-access"}); err != nil {
		t.Fatal(err)
	}
	if _, err := oldStore.Load(); !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("previous keyring entry not removed: %v", err)
	}
	got, err := store.Load()
	if err != nil || got.AccessToken != "new-access" || got.Issuer != "https://oauth.sneat.co" {
		t.Fatalf("Load() = %#v, %v", got, err)
	}
}

func TestDeviceLoginFallsBackWhileIssuerIsNotServing(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		primary func(t *testing.T, hits *atomic.Int32) string
		hits    int32
	}{
		{name: "connection refused", primary: func(t *testing.T, _ *atomic.Int32) string { return closedURL(t) }},
		{name: "HTTP 404", primary: func(t *testing.T, hits *atomic.Int32) string { return notFoundServer(t, hits).URL }, hits: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var hits atomic.Int32
			primary := tc.primary(t, &hits)
			fallback := newOAuthService(t)
			client := newMigrationClient(t, ClientConfig{Issuer: primary, FallbackIssuers: []string{fallback.server.URL}})
			if client.ServingIssuer() != client.Issuer() {
				t.Fatalf("ServingIssuer() before any request = %q", client.ServingIssuer())
			}
			store := &memoryStore{}
			auth, err := client.DeviceLoginAndStore(context.Background(), DeviceLoginOptions{Output: io.Discard, ErrorOutput: io.Discard}, store)
			if err != nil {
				t.Fatalf("DeviceLoginAndStore() error = %v", err)
			}
			if auth.Identity.Subject != "user-1" {
				t.Fatalf("identity = %#v", auth.Identity)
			}
			if store.credential.Issuer != client.Issuer() {
				t.Fatalf("credential issuer = %q, want the new issuer %q", store.credential.Issuer, client.Issuer())
			}
			if client.ServingIssuer() != fallback.server.URL {
				t.Fatalf("ServingIssuer() = %q, want %q", client.ServingIssuer(), fallback.server.URL)
			}
			if hits.Load() != tc.hits {
				t.Fatalf("primary was asked %d times, want %d (decided once per client)", hits.Load(), tc.hits)
			}
			if served := fallback.served(); len(served) != 3 || served[0] != "/oauth/device/code" || served[2] != "/oauth/userinfo" {
				t.Fatalf("fallback served = %v", served)
			}
		})
	}
}

func TestFallbackIsNotUsedOnceIssuerServes(t *testing.T) {
	t.Parallel()

	primary := newOAuthService(t)
	var fallbackHits atomic.Int32
	fallback := notFoundServer(t, &fallbackHits)
	client := newMigrationClient(t, ClientConfig{Issuer: primary.server.URL, FallbackIssuers: []string{fallback.URL}})
	if _, err := client.UserInfo(context.Background(), &oauth2.Token{AccessToken: "token"}); err != nil {
		t.Fatalf("UserInfo() error = %v", err)
	}
	if client.ServingIssuer() != client.Issuer() {
		t.Fatalf("ServingIssuer() = %q", client.ServingIssuer())
	}
	// A later 404 from the serving issuer is an answer, not a reason to move.
	req, _ := http.NewRequest(http.MethodGet, primary.server.URL+"/oauth/missing", nil)
	response, err := client.httpClient(context.Background()).Do(req)
	if err != nil || response.StatusCode != http.StatusNotFound {
		t.Fatalf("Do() = %v, %v", response, err)
	}
	_ = response.Body.Close()
	if fallbackHits.Load() != 0 {
		t.Fatalf("fallback hits = %d", fallbackHits.Load())
	}
}

func TestFallbackReturnsIssuerResultWhenNothingServes(t *testing.T) {
	t.Parallel()

	var primaryHits, fallbackHits atomic.Int32
	primary := notFoundServer(t, &primaryHits)
	fallback := notFoundServer(t, &fallbackHits)
	client := newMigrationClient(t, ClientConfig{Issuer: primary.URL, FallbackIssuers: []string{fallback.URL, closedURL(t)}})
	err := client.Revoke(context.Background(), "token")
	var responseErr *ResponseError
	if !errors.As(err, &responseErr) || responseErr.StatusCode != http.StatusNotFound {
		t.Fatalf("Revoke() error = %v", err)
	}
	if primaryHits.Load() != 1 || fallbackHits.Load() != 1 {
		t.Fatalf("hits = %d/%d", primaryHits.Load(), fallbackHits.Load())
	}
	if client.ServingIssuer() != client.Issuer() {
		t.Fatal("an undecided client must report its issuer")
	}

	refused := newMigrationClient(t, ClientConfig{Issuer: closedURL(t), FallbackIssuers: []string{closedURL(t)}})
	if _, err := refused.UserInfo(context.Background(), &oauth2.Token{AccessToken: "token"}); err == nil || !strings.Contains(err.Error(), "request userinfo") {
		t.Fatalf("UserInfo() error = %v", err)
	}
}

func TestFallbackRespectsCallerCancellation(t *testing.T) {
	t.Parallel()

	var fallbackHits atomic.Int32
	fallback := notFoundServer(t, &fallbackHits)
	client := newMigrationClient(t, ClientConfig{Issuer: closedURL(t), FallbackIssuers: []string{fallback.URL}})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := client.Revoke(ctx, "token"); err == nil {
		t.Fatal("Revoke() error = nil")
	}
	if fallbackHits.Load() != 0 {
		t.Fatalf("fallback hits = %d after cancellation", fallbackHits.Load())
	}
}

func TestFallbackTransportRouting(t *testing.T) {
	t.Parallel()

	primary, _ := url.Parse("https://new.example/base")
	fallbackURL, _ := url.Parse("https://old.example/legacy")
	router := &issuerRouter{primary: primary, fallbacks: []*url.URL{fallbackURL}}
	for rawURL, want := range map[string]bool{
		"https://new.example/base":             true,
		"https://NEW.example/base/oauth/token": true,
		"https://new.example/basement":         false,
		"https://other.example/base/oauth":     false,
		"http://new.example/base/oauth":        false,
	} {
		parsed, _ := url.Parse(rawURL)
		if got := router.routes(parsed); got != want {
			t.Errorf("routes(%s) = %v, want %v", rawURL, got, want)
		}
	}
	tokenURL, _ := url.Parse("https://new.example/base/oauth/token?x=1")
	if got := router.rebase(tokenURL, fallbackURL).String(); got != "https://old.example/legacy/oauth/token?x=1" {
		t.Fatalf("rebase() = %q", got)
	}

	var seen []string
	transport := fallbackTransport{router: router, base: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		seen = append(seen, req.URL.String())
		body := ""
		if req.Body != nil {
			raw, _ := io.ReadAll(req.Body)
			body = string(raw)
		}
		if req.URL.Host == "new.example" {
			return nil, errors.New("dial tcp: no such host")
		}
		if req.GetBody != nil {
			replay, _ := req.GetBody()
			if raw, _ := io.ReadAll(replay); string(raw) != body {
				t.Errorf("GetBody() = %q, want %q", raw, body)
			}
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Request: req}, nil
	})}

	other, _ := http.NewRequest(http.MethodGet, "https://other.example/x", nil)
	if response, err := transport.RoundTrip(other); err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("pass-through RoundTrip() = %v, %v", response, err)
	}
	post, _ := http.NewRequest(http.MethodPost, "https://new.example/base/oauth/token", strings.NewReader("grant=1"))
	response, err := transport.RoundTrip(post)
	if err != nil {
		t.Fatalf("RoundTrip() error = %v", err)
	}
	if raw, _ := io.ReadAll(response.Body); string(raw) != "grant=1" {
		t.Fatalf("fallback body = %q", raw)
	}
	want := []string{"https://other.example/x", "https://new.example/base/oauth/token", "https://old.example/legacy/oauth/token"}
	if strings.Join(seen, " ") != strings.Join(want, " ") {
		t.Fatalf("seen = %v", seen)
	}

	unreadable, _ := http.NewRequest(http.MethodPost, "https://new.example/base/oauth/token", io.NopCloser(failingReader{}))
	if _, err := transport.RoundTrip(unreadable); err == nil || !strings.Contains(err.Error(), "read request body") {
		t.Fatalf("RoundTrip(unreadable) error = %v", err)
	}
}

func TestClientHTTPClientKeepsCallerSettings(t *testing.T) {
	t.Parallel()

	client := newMigrationClient(t, ClientConfig{Issuer: "https://new.example", FallbackIssuers: []string{"https://old.example"}})
	defaultWrapped := client.httpClient(context.Background())
	if transport, ok := defaultWrapped.Transport.(fallbackTransport); !ok || transport.base != http.DefaultTransport {
		t.Fatalf("default transport = %#v", defaultWrapped.Transport)
	}
	custom := &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New("unused") }), Timeout: 7}
	wrapped := client.httpClient(context.WithValue(context.Background(), oauth2.HTTPClient, custom))
	if wrapped.Timeout != 7 {
		t.Fatalf("timeout = %v", wrapped.Timeout)
	}
	if _, ok := wrapped.Transport.(fallbackTransport); !ok {
		t.Fatalf("transport = %#v", wrapped.Transport)
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("broken body") }
