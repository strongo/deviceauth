package deviceauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"

	"golang.org/x/oauth2"
)

// ErrCredentialScopeMismatch reports a credential that was saved for a
// different issuer or OAuth client. Callers must not use it as a session for
// the current Client.
var ErrCredentialScopeMismatch = errors.New("deviceauth: credential issuer or client ID does not match")

// ClientConfig configures a reusable device-authorization client for one
// OAuth issuer and public CLI client. Issuer is the base URL, for example
// "https://auth.sneat.co". KeyringService and KeyringAccount are product
// chosen names used only when NewKeyringStore is called.
type ClientConfig struct {
	Issuer         string
	ClientID       string
	Scopes         []string
	KeyringService string
	KeyringAccount string
}

// Client provides the neutral client-side half of a device authorization
// service. It knows the standard endpoint layout below its issuer, but does
// not depend on a particular identity provider or product.
type Client struct {
	issuer         *url.URL
	clientID       string
	scopes         []string
	keyringService string
	keyringAccount string
}

// NewClient validates config and returns a client for an OAuth service.
func NewClient(config ClientConfig) (*Client, error) {
	issuer, err := parseIssuer(config.Issuer)
	if err != nil {
		return nil, err
	}
	clientID := strings.TrimSpace(config.ClientID)
	if clientID == "" {
		return nil, errors.New("deviceauth: client ID is required")
	}
	scopes := compactStrings(config.Scopes)
	if len(scopes) == 0 {
		return nil, errors.New("deviceauth: at least one scope is required")
	}
	return &Client{
		issuer:         issuer,
		clientID:       clientID,
		scopes:         scopes,
		keyringService: strings.TrimSpace(config.KeyringService),
		keyringAccount: strings.TrimSpace(config.KeyringAccount),
	}, nil
}

// Issuer returns the canonical base URL configured for this client.
func (c *Client) Issuer() string { return c.issuer.String() }

// OAuthConfig returns the configuration needed by the existing Login API.
func (c *Client) OAuthConfig() oauth2.Config {
	return oauth2.Config{
		ClientID: c.clientID,
		Scopes:   append([]string(nil), c.scopes...),
		Endpoint: oauth2.Endpoint{
			DeviceAuthURL: c.endpoint("oauth/device/code"),
			TokenURL:      c.endpoint("oauth/token"),
		},
	}
}

// DeviceLoginOptions are the presentation and device details used during a
// device authorization. The issuer, client ID, scopes, and endpoints always
// come from Client.
type DeviceLoginOptions struct {
	DeviceInfo       DeviceInfo
	OpenBrowser      func(string) error
	Output           io.Writer
	ErrorOutput      io.Writer
	TokenTransformer TokenTransformer
}

// TokenTransformer converts the token returned by the device token endpoint
// into the session token accepted by userinfo and the product API. It is
// deliberately identity-provider-neutral: a consumer may exchange a one-use
// bootstrap token for its own session without this package importing that
// provider's SDK.
//
// The input is always the unmodified token returned by DeviceLogin. The
// transformer must return a non-nil token with a non-empty access token.
type TokenTransformer func(context.Context, *oauth2.Token) (*oauth2.Token, error)

// DeviceLogin starts and completes the RFC 8628 flow using this client's
// configured service. It preserves the package Login function for existing
// consumers such as OVDB.
func (c *Client) DeviceLogin(ctx context.Context, options DeviceLoginOptions) (LoginResult, error) {
	return Login(ctx, LoginOptions{
		OAuthConfig: c.OAuthConfig(),
		DeviceInfo:  options.DeviceInfo,
		OpenBrowser: options.OpenBrowser,
		Output:      options.Output,
		ErrorOutput: options.ErrorOutput,
	})
}

// Identity is a validated response from the issuer's userinfo endpoint.
// Audience is always non-empty and contains ClientID after UserInfo returns.
type Identity struct {
	Subject  string
	Name     string
	Email    string
	Audience []string
	Scopes   []string
}

// UserInfo validates the identity associated with token. The service contract
// is an OAuth-style JSON response with a non-empty "sub" and an "aud" string
// or array that includes this client's ID. "scope" may be a space-separated
// string or an array.
func (c *Client) UserInfo(ctx context.Context, token *oauth2.Token) (Identity, error) {
	if token == nil || strings.TrimSpace(token.AccessToken) == "" {
		return Identity{}, errors.New("deviceauth: access token is required for userinfo")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint("oauth/userinfo"), nil)
	if err != nil {
		return Identity{}, fmt.Errorf("create userinfo request: %w", err)
	}
	req.Header.Set("Authorization", token.TokenType+" "+token.AccessToken)
	if strings.TrimSpace(token.TokenType) == "" {
		req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	}
	req.Header.Set("Accept", "application/json")

	response, err := httpClient(ctx).Do(req)
	if err != nil {
		return Identity{}, fmt.Errorf("request userinfo: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return Identity{}, responseError("userinfo", response)
	}
	var payload struct {
		Subject  string          `json:"sub"`
		Name     string          `json:"name"`
		Email    string          `json:"email"`
		Audience json.RawMessage `json:"aud"`
		Scope    json.RawMessage `json:"scope"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&payload); err != nil {
		return Identity{}, fmt.Errorf("decode userinfo: %w", err)
	}
	identity := Identity{
		Subject: strings.TrimSpace(payload.Subject),
		Name:    strings.TrimSpace(payload.Name),
		Email:   strings.TrimSpace(payload.Email),
	}
	if identity.Subject == "" {
		return Identity{}, errors.New("deviceauth: userinfo subject is required")
	}
	var errAudience error
	identity.Audience, errAudience = decodeStringOrArray(payload.Audience, "aud", false)
	if errAudience != nil {
		return Identity{}, errAudience
	}
	if !contains(identity.Audience, c.clientID) {
		return Identity{}, fmt.Errorf("deviceauth: userinfo audience does not include client ID %q", c.clientID)
	}
	identity.Scopes, err = decodeStringOrArray(payload.Scope, "scope", true)
	if err != nil {
		return Identity{}, err
	}
	return identity, nil
}

// Authentication is the complete, validated result of DeviceLoginAndStore.
type Authentication struct {
	Login        LoginResult
	SessionToken *oauth2.Token
	Identity     Identity
	Credential   Credential
}

// DeviceLoginAndStore completes device authorization, validates userinfo, and
// saves a credential bound to this issuer and client. The supplied store is
// scoped automatically; this prevents accidental reuse of the same file or
// keyring account by another issuer/client pair.
func (c *Client) DeviceLoginAndStore(ctx context.Context, options DeviceLoginOptions, store Store) (Authentication, error) {
	if store == nil {
		return Authentication{}, errors.New("deviceauth: credential store is required")
	}
	login, err := c.DeviceLogin(ctx, options)
	if err != nil {
		return Authentication{Login: login}, err
	}
	sessionToken := login.Token
	if options.TokenTransformer != nil {
		sessionToken, err = options.TokenTransformer(ctx, login.Token)
		if err != nil {
			return Authentication{Login: login}, fmt.Errorf("transform device token: %w", err)
		}
		if sessionToken == nil || strings.TrimSpace(sessionToken.AccessToken) == "" {
			return Authentication{Login: login}, errors.New("deviceauth: token transformer returned an empty access token")
		}
	}
	identity, err := c.UserInfo(ctx, sessionToken)
	if err != nil {
		return Authentication{Login: login, SessionToken: sessionToken}, err
	}
	credential := Credential{
		AccessToken:  sessionToken.AccessToken,
		TokenType:    sessionToken.TokenType,
		RefreshToken: sessionToken.RefreshToken,
		Expiry:       sessionToken.Expiry,
		AccountID:    identity.Subject,
		AccountName:  firstNonEmpty(identity.Name, identity.Email),
		Scopes:       append([]string(nil), identity.Scopes...),
	}
	if len(credential.Scopes) == 0 {
		credential.Scopes = append([]string(nil), c.scopes...)
	}
	credential = c.bindCredential(credential)
	if err := store.Save(credential); err != nil {
		return Authentication{Login: login, SessionToken: sessionToken, Identity: identity, Credential: credential}, fmt.Errorf("save device credential: %w", err)
	}
	return Authentication{Login: login, SessionToken: sessionToken, Identity: identity, Credential: credential}, nil
}

// ScopedStore wraps store so every saved credential is bound to this issuer
// and client. Load rejects a credential saved for a different pair.
func (c *Client) ScopedStore(store Store) Store {
	return scopedStore{store: store, issuer: c.Issuer(), clientID: c.clientID}
}

// NewKeyringStore returns an issuer/client-isolated keyring store. It requires
// the product-specific KeyringService and KeyringAccount from ClientConfig.
func (c *Client) NewKeyringStore() (Store, error) {
	if c.keyringService == "" || c.keyringAccount == "" {
		return nil, errors.New("deviceauth: keyring service and account are required to create a keyring store")
	}
	store, err := NewKeyringStore(c.keyringService, c.keyringIdentity())
	if err != nil {
		return nil, err
	}
	return c.ScopedStore(store), nil
}

// Logout revokes the stored access token at the issuer before removing the
// local credential. A failed revoke leaves the local credential in place so a
// caller can retry rather than falsely reporting a successful logout.
func (c *Client) Logout(ctx context.Context, store Store) error {
	if store == nil {
		return errors.New("deviceauth: credential store is required")
	}
	credential, err := c.ScopedStore(store).Load()
	if errors.Is(err, ErrCredentialNotFound) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("load device credential for logout: %w", err)
	}
	if err := c.Revoke(ctx, credential.AccessToken); err != nil {
		return err
	}
	if err := store.Delete(); err != nil {
		return fmt.Errorf("delete device credential after revocation: %w", err)
	}
	return nil
}

// Revoke invalidates token at the configured OAuth service.
func (c *Client) Revoke(ctx context.Context, token string) error {
	token = strings.TrimSpace(token)
	if token == "" {
		return errors.New("deviceauth: access token is required for revocation")
	}
	form := url.Values{"token": {token}, "token_type_hint": {"access_token"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint("oauth/revoke"), strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("create revoke request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	response, err := httpClient(ctx).Do(req)
	if err != nil {
		return fmt.Errorf("request token revocation: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return responseError("revoke", response)
	}
	return nil
}

func (c *Client) endpoint(suffix string) string {
	endpoint := *c.issuer
	endpoint.Path = path.Join(endpoint.Path, suffix)
	endpoint.RawPath = ""
	return endpoint.String()
}

func (c *Client) keyringIdentity() string {
	return c.keyringAccount + "|issuer=" + url.QueryEscape(c.Issuer()) + "|client_id=" + url.QueryEscape(c.clientID)
}

func (c *Client) bindCredential(credential Credential) Credential {
	credential.Issuer = c.Issuer()
	credential.ClientID = c.clientID
	return credential
}

type scopedStore struct {
	store    Store
	issuer   string
	clientID string
}

func (s scopedStore) Save(credential Credential) error {
	credential.Issuer = s.issuer
	credential.ClientID = s.clientID
	return s.store.Save(credential)
}

func (s scopedStore) Load() (Credential, error) {
	credential, err := s.store.Load()
	if err != nil {
		return Credential{}, err
	}
	if credential.Issuer != s.issuer || credential.ClientID != s.clientID {
		return Credential{}, ErrCredentialScopeMismatch
	}
	return credential, nil
}

func (s scopedStore) Delete() error { return s.store.Delete() }

func parseIssuer(rawIssuer string) (*url.URL, error) {
	issuer, err := url.Parse(strings.TrimSpace(rawIssuer))
	if err != nil || issuer.Scheme == "" || issuer.Host == "" {
		return nil, errors.New("deviceauth: issuer must be an absolute URL")
	}
	if issuer.Scheme != "https" && issuer.Scheme != "http" {
		return nil, errors.New("deviceauth: issuer URL scheme must be http or https")
	}
	if issuer.RawQuery != "" || issuer.Fragment != "" {
		return nil, errors.New("deviceauth: issuer URL must not contain a query or fragment")
	}
	issuer.Path = strings.TrimRight(issuer.Path, "/")
	issuer.RawPath = ""
	return issuer, nil
}

func decodeStringOrArray(raw json.RawMessage, field string, optional bool) ([]string, error) {
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		if optional {
			return nil, nil
		}
		return nil, fmt.Errorf("deviceauth: userinfo %s is required", field)
	}
	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		values := compactStrings(strings.Fields(single))
		if len(values) == 0 && !optional {
			return nil, fmt.Errorf("deviceauth: userinfo %s is required", field)
		}
		return values, nil
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err != nil {
		return nil, fmt.Errorf("deviceauth: userinfo %s must be a string or string array", field)
	}
	values := compactStrings(many)
	if len(values) == 0 && !optional {
		return nil, fmt.Errorf("deviceauth: userinfo %s is required", field)
	}
	return values, nil
}

func compactStrings(values []string) []string {
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func httpClient(ctx context.Context) *http.Client {
	if client, ok := ctx.Value(oauth2.HTTPClient).(*http.Client); ok && client != nil {
		return client
	}
	return http.DefaultClient
}

func responseError(operation string, response *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
	message := strings.TrimSpace(string(body))
	if message == "" {
		return fmt.Errorf("%s request failed: %s", operation, response.Status)
	}
	return fmt.Errorf("%s request failed: %s: %s", operation, response.Status, message)
}
