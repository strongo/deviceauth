package deviceauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/oauth2"
)

func TestLoginCompletesDeviceAuthorization(t *testing.T) {
	t.Parallel()

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/device/code":
			if got := r.FormValue("client_id"); got != "test-cli" {
				t.Fatalf("client_id = %q, want test-cli", got)
			}
			if got := r.FormValue("scope"); got != "account:read" {
				t.Fatalf("scope = %q, want account:read", got)
			}
			for name, want := range map[string]string{
				"device_name":    "Alex's MacBook Pro",
				"os":             "darwin",
				"arch":           "arm64",
				"client_version": "0.2.0",
			} {
				if got := r.FormValue(name); got != want {
					t.Fatalf("%s = %q, want %q", name, got, want)
				}
			}
			writeJSON(t, w, map[string]any{
				"device_code":               "device-secret",
				"user_code":                 "ABCD-EFGH",
				"verification_uri":          server.URL + "/device",
				"verification_uri_complete": server.URL + "/device?user_code=ABCD-EFGH",
				"expires_in":                600,
				"interval":                  1,
			})
		case "/oauth/token":
			if got := r.FormValue("grant_type"); got != "urn:ietf:params:oauth:grant-type:device_code" {
				t.Fatalf("grant_type = %q", got)
			}
			if got := r.FormValue("device_code"); got != "device-secret" {
				t.Fatalf("device_code = %q", got)
			}
			writeJSON(t, w, map[string]any{
				"access_token": "access-secret",
				"token_type":   "Bearer",
				"expires_in":   3600,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	var errorOutput bytes.Buffer
	var opened string
	result, err := Login(context.Background(), LoginOptions{
		OAuthConfig: oauth2.Config{
			ClientID: "test-cli",
			Scopes:   []string{"account:read"},
			Endpoint: oauth2.Endpoint{
				DeviceAuthURL: server.URL + "/oauth/device/code",
				TokenURL:      server.URL + "/oauth/token",
			},
		},
		DeviceInfo: DeviceInfo{
			Name: " Alex's MacBook Pro ", OS: "darwin", Arch: "arm64", ClientVersion: "0.2.0",
		},
		OpenBrowser: func(rawURL string) error {
			opened = rawURL
			return nil
		},
		Output:      &output,
		ErrorOutput: &errorOutput,
	})
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}
	if got := result.Token.AccessToken; got != "access-secret" {
		t.Fatalf("access token = %q", got)
	}
	if !result.BrowserOpened {
		t.Fatal("BrowserOpened = false")
	}
	if want := server.URL + "/device?user_code=ABCD-EFGH"; opened != want {
		t.Fatalf("opened = %q, want %q", opened, want)
	}
	if !strings.Contains(output.String(), "ABCD-EFGH") || !strings.Contains(output.String(), opened) {
		t.Fatalf("instructions = %q", output.String())
	}
	if errorOutput.Len() != 0 {
		t.Fatalf("error output = %q", errorOutput.String())
	}
}

func TestLoginOmitsEmptyDeviceInfo(t *testing.T) {
	t.Parallel()

	server := immediateAuthorizationServer(t)
	defer server.Close()

	client := server.Client()
	originalTransport := client.Transport
	client.Transport = roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Path == "/device" {
			if err := request.ParseForm(); err != nil {
				t.Fatalf("parse device authorization form: %v", err)
			}
			for _, name := range []string{"device_name", "os", "arch", "client_version"} {
				if _, exists := request.Form[name]; exists {
					t.Fatalf("empty %s must be omitted", name)
				}
			}
			if request.GetBody != nil {
				body, err := request.GetBody()
				if err != nil {
					t.Fatalf("restore device authorization form: %v", err)
				}
				request.Body = body
			}
		}
		return originalTransport.RoundTrip(request)
	})

	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, client)
	_, err := Login(ctx, LoginOptions{
		OAuthConfig: oauth2.Config{
			ClientID: "test-cli",
			Endpoint: oauth2.Endpoint{
				DeviceAuthURL: server.URL + "/device",
				TokenURL:      server.URL + "/token",
			},
		},
		DeviceInfo:  DeviceInfo{Name: "  "},
		Output:      &bytes.Buffer{},
		ErrorOutput: &bytes.Buffer{},
	})
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}
}

func TestLoginBrowserFailureKeepsPolling(t *testing.T) {
	t.Parallel()

	server := immediateAuthorizationServer(t)
	defer server.Close()

	var errorOutput bytes.Buffer
	result, err := Login(context.Background(), LoginOptions{
		OAuthConfig: oauth2.Config{
			ClientID: "test-cli",
			Endpoint: oauth2.Endpoint{
				DeviceAuthURL: server.URL + "/device",
				TokenURL:      server.URL + "/token",
			},
		},
		OpenBrowser: func(string) error { return errors.New("headless") },
		Output:      &bytes.Buffer{},
		ErrorOutput: &errorOutput,
	})
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}
	if result.BrowserOpened {
		t.Fatal("BrowserOpened = true")
	}
	if result.Token.AccessToken != "access-secret" {
		t.Fatalf("access token = %q", result.Token.AccessToken)
	}
	if !strings.Contains(errorOutput.String(), "headless") || !strings.Contains(errorOutput.String(), "URL above") {
		t.Fatalf("error output = %q", errorOutput.String())
	}
}

func TestLoginValidatesConfigurationBeforeRequest(t *testing.T) {
	t.Parallel()

	_, err := Login(context.Background(), LoginOptions{})
	if err == nil || !strings.Contains(err.Error(), "client ID") {
		t.Fatalf("error = %v", err)
	}
}

func TestLoginUsesAbsoluteEndpoints(t *testing.T) {
	t.Parallel()

	_, err := Login(context.Background(), LoginOptions{
		OAuthConfig: oauth2.Config{
			ClientID: "test-cli",
			Endpoint: oauth2.Endpoint{
				DeviceAuthURL: "/device",
				TokenURL:      "https://example.com/token",
			},
		},
		Output:      &bytes.Buffer{},
		ErrorOutput: &bytes.Buffer{},
	})
	if err == nil || !strings.Contains(err.Error(), "absolute URL") {
		t.Fatalf("error = %v", err)
	}
}

func TestBrowserCommand(t *testing.T) {
	t.Parallel()

	tests := []struct {
		goos string
		name string
	}{
		{goos: "darwin", name: "open"},
		{goos: "linux", name: "xdg-open"},
		{goos: "windows", name: "rundll32"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.goos, func(t *testing.T) {
			t.Parallel()
			name, args, err := browserCommand(test.goos, "https://example.com/device")
			if err != nil {
				t.Fatalf("browserCommand() error = %v", err)
			}
			if name != test.name || len(args) == 0 {
				t.Fatalf("command = %q %v", name, args)
			}
		})
	}
}

func TestOpenBrowserRejectsRelativeURL(t *testing.T) {
	t.Parallel()

	if err := OpenBrowser("/device"); err == nil {
		t.Fatal("OpenBrowser() error = nil")
	}
}

func immediateAuthorizationServer(t *testing.T) *httptest.Server {
	t.Helper()

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/device":
			writeJSON(t, w, map[string]any{
				"device_code":      "device-secret",
				"user_code":        "ABCD-EFGH",
				"verification_uri": server.URL + "/verify",
				"expires_in":       600,
				"interval":         1,
			})
		case "/token":
			writeJSON(t, w, map[string]any{
				"access_token": "access-secret",
				"token_type":   "Bearer",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	return server
}

func writeJSON(t *testing.T, w http.ResponseWriter, value any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		t.Fatalf("encode response: %v", err)
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}
