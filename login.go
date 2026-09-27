// Package deviceauth provides reusable OAuth 2.0 device-login UX and
// credential storage for command-line applications.
package deviceauth

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"

	"golang.org/x/oauth2"
)

// DeviceInfo describes the command-line device requesting authorization.
// Authorization servers may display these optional, untrusted values during
// consent and retain them with the resulting grant.
type DeviceInfo struct {
	Name          string
	OS            string
	Arch          string
	ClientVersion string
}

func (v DeviceInfo) authCodeOptions() []oauth2.AuthCodeOption {
	values := []struct {
		name  string
		value string
	}{
		{name: "device_name", value: v.Name},
		{name: "os", value: v.OS},
		{name: "arch", value: v.Arch},
		{name: "client_version", value: v.ClientVersion},
	}
	options := make([]oauth2.AuthCodeOption, 0, len(values))
	for _, value := range values {
		if trimmed := strings.TrimSpace(value.value); trimmed != "" {
			options = append(options, oauth2.SetAuthURLParam(value.name, trimmed))
		}
	}
	return options
}

// LoginOptions configures one browser-approved OAuth 2.0 device login.
// Product-specific commands own the OAuth endpoints, client ID, and scopes.
type LoginOptions struct {
	OAuthConfig oauth2.Config
	DeviceInfo  DeviceInfo
	OpenBrowser func(string) error
	Output      io.Writer
	ErrorOutput io.Writer
}

// LoginResult contains the issued token and the authorization prompt that led
// to it. BrowserOpened reports only whether the launcher succeeded; a failed
// launcher is intentionally non-fatal because the visible URL remains usable.
type LoginResult struct {
	Token         *oauth2.Token
	Authorization *oauth2.DeviceAuthResponse
	BrowserOpened bool
}

// Login starts an RFC 8628 device authorization, shows the user code and URL,
// attempts to open the verification page, and polls until approval, denial,
// expiry, or context cancellation.
func Login(ctx context.Context, options LoginOptions) (LoginResult, error) {
	if err := validateLoginOptions(options); err != nil {
		return LoginResult{}, err
	}

	authorization, err := options.OAuthConfig.DeviceAuth(ctx, options.DeviceInfo.authCodeOptions()...)
	if err != nil {
		return LoginResult{}, fmt.Errorf("request device authorization: %w", err)
	}

	verificationURL := authorization.VerificationURIComplete
	if verificationURL == "" {
		verificationURL = authorization.VerificationURI
	}
	if _, err := fmt.Fprintf(
		options.Output,
		"Copy this one-time code: %s\nOpen %s in your browser to continue.\n",
		authorization.UserCode,
		verificationURL,
	); err != nil {
		return LoginResult{}, fmt.Errorf("write device authorization instructions: %w", err)
	}

	browserOpened := false
	if options.OpenBrowser != nil {
		if err := options.OpenBrowser(verificationURL); err != nil {
			_, _ = fmt.Fprintf(
				options.ErrorOutput,
				"Could not open a browser automatically: %v\nContinue with the URL above.\n",
				err,
			)
		} else {
			browserOpened = true
		}
	}

	token, err := options.OAuthConfig.DeviceAccessToken(ctx, authorization)
	if err != nil {
		return LoginResult{
			Authorization: authorization,
			BrowserOpened: browserOpened,
		}, fmt.Errorf("complete device authorization: %w", err)
	}

	return LoginResult{
		Token:         token,
		Authorization: authorization,
		BrowserOpened: browserOpened,
	}, nil
}

func validateLoginOptions(options LoginOptions) error {
	if options.OAuthConfig.ClientID == "" {
		return errors.New("deviceauth: OAuth client ID is required")
	}
	if options.OAuthConfig.Endpoint.DeviceAuthURL == "" {
		return errors.New("deviceauth: device authorization endpoint is required")
	}
	if options.OAuthConfig.Endpoint.TokenURL == "" {
		return errors.New("deviceauth: token endpoint is required")
	}
	for name, rawURL := range map[string]string{
		"device authorization endpoint": options.OAuthConfig.Endpoint.DeviceAuthURL,
		"token endpoint":                options.OAuthConfig.Endpoint.TokenURL,
	} {
		parsed, err := url.Parse(rawURL)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			return fmt.Errorf("deviceauth: %s must be an absolute URL", name)
		}
	}
	if options.Output == nil {
		return errors.New("deviceauth: output writer is required")
	}
	if options.ErrorOutput == nil {
		return errors.New("deviceauth: error output writer is required")
	}
	return nil
}
