package deviceauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

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
	Issuer   string
	ClientID string
	Scopes   []string
	// RequiredScopes is the subset of requested Scopes a caller requires for a
	// usable session. It is checked against the issuer's authoritative
	// userinfo scope claim; an omitted scope claim is never treated as a grant.
	RequiredScopes []string
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
	requiredScopes []string
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
	requiredScopes := compactStrings(config.RequiredScopes)
	if err := validateRequiredScopesRequested(scopes, requiredScopes); err != nil {
		return nil, err
	}
	return &Client{
		issuer:         issuer,
		clientID:       clientID,
		scopes:         scopes,
		requiredScopes: requiredScopes,
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
			AuthStyle:     oauth2.AuthStyleInParams,
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
	defer func() { _ = response.Body.Close() }()
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
	// Warnings report completed logins that need operator attention but are
	// safe to use. In particular, a new local credential remains valid when a
	// replaced server token could not be revoked.
	Warnings []error
}

// ReplacementRevocationWarning reports that a new credential was saved but
// the previous credential could not be revoked. The authentication succeeded;
// callers may surface this warning and retry revocation later.
type ReplacementRevocationWarning struct {
	Cause error
}

func (e *ReplacementRevocationWarning) Error() string {
	return "deviceauth: new credential was saved but the previous credential could not be revoked"
}

func (e *ReplacementRevocationWarning) Unwrap() error { return e.Cause }

// DeviceLoginAndStore completes device authorization, validates userinfo, and
// saves a credential bound to this issuer and client. The supplied store is
// scoped automatically; this prevents accidental reuse of the same file or
// keyring account by another issuer/client pair.
func (c *Client) DeviceLoginAndStore(ctx context.Context, options DeviceLoginOptions, store Store) (Authentication, error) {
	if store == nil {
		return Authentication{}, errors.New("deviceauth: credential store is required")
	}
	scopedStore := c.ScopedStore(store)
	previous, err := scopedStore.Load()
	if err != nil && !errors.Is(err, ErrCredentialNotFound) {
		return Authentication{}, fmt.Errorf("load existing device credential: %w", err)
	}
	hasPrevious := err == nil

	login, err := c.DeviceLogin(ctx, options)
	if err != nil {
		return Authentication{Login: login}, err
	}
	sessionToken := login.Token
	if options.TokenTransformer != nil {
		sessionToken, err = options.TokenTransformer(ctx, login.Token)
		if err != nil {
			return Authentication{Login: login}, c.withTokenCleanup(ctx, fmt.Errorf("transform device token: %w", err), login.Token)
		}
		if sessionToken == nil || strings.TrimSpace(sessionToken.AccessToken) == "" {
			return Authentication{Login: login}, c.withTokenCleanup(ctx, errors.New("deviceauth: token transformer returned an empty access token"), login.Token)
		}
	}
	identity, err := c.UserInfo(ctx, sessionToken)
	if err != nil {
		return Authentication{Login: login, SessionToken: sessionToken}, c.withTokenCleanup(ctx, err, login.Token, sessionToken)
	}
	if err := ValidateRequiredScopes(identity.Scopes, c.requiredScopes); err != nil {
		return Authentication{Login: login, SessionToken: sessionToken, Identity: identity}, c.withTokenCleanup(ctx, err, login.Token, sessionToken)
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
	credential = c.bindCredential(credential)
	if err := scopedStore.Save(credential); err != nil {
		return Authentication{Login: login, SessionToken: sessionToken, Identity: identity, Credential: credential}, c.withTokenCleanup(ctx, fmt.Errorf("save device credential: %w", err), login.Token, sessionToken)
	}
	if hasPrevious && previous.AccessToken != credential.AccessToken {
		if err := c.Revoke(ctx, previous.AccessToken); err != nil {
			return Authentication{
				Login:        login,
				SessionToken: sessionToken,
				Identity:     identity,
				Credential:   credential,
				Warnings:     []error{&ReplacementRevocationWarning{Cause: err}},
			}, nil
		}
	}
	return Authentication{Login: login, SessionToken: sessionToken, Identity: identity, Credential: credential}, nil
}

// ValidateRequiredScopes verifies that every explicitly required scope was
// granted by the issuer. With no requirements it succeeds; an absent or
// reduced granted scope claim never becomes a synthetic requested grant.
func ValidateRequiredScopes(granted, required []string) error {
	for _, scope := range compactStrings(required) {
		if !contains(granted, scope) {
			return fmt.Errorf("deviceauth: required scope %q was not granted", scope)
		}
	}
	return nil
}

func validateRequiredScopesRequested(requested, required []string) error {
	for _, scope := range required {
		if !contains(requested, scope) {
			return fmt.Errorf("deviceauth: required scope %q is not requested", scope)
		}
	}
	return nil
}

func (c *Client) withTokenCleanup(ctx context.Context, primary error, tokens ...*oauth2.Token) error {
	var cleanupErrors []error
	seen := make(map[string]struct{}, len(tokens))
	cleanupCtx, cancel := cleanupContext(ctx)
	defer cancel()
	for _, token := range tokens {
		if token == nil || strings.TrimSpace(token.AccessToken) == "" {
			continue
		}
		if _, exists := seen[token.AccessToken]; exists {
			continue
		}
		seen[token.AccessToken] = struct{}{}
		if err := c.Revoke(cleanupCtx, token.AccessToken); err != nil {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("revoke incomplete device login: %w", err))
		}
	}
	primary = redactTokens(primary, seen)
	if len(cleanupErrors) == 0 {
		return primary
	}
	return errors.Join(append([]error{primary}, cleanupErrors...)...)
}

const cleanupTimeout = 5 * time.Second

// cleanupContext keeps local context values (including tracing values) for
// transport instrumentation, but removes its cancellation and deadline. The
// bounded timeout prevents cleanup from turning a failed login into an
// unbounded background request.
func cleanupContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), cleanupTimeout)
}

type tokenRedactedError struct {
	err      error
	tokenSet map[string]struct{}
}

func (e tokenRedactedError) Error() string {
	message := e.err.Error()
	for token := range e.tokenSet {
		message = strings.ReplaceAll(message, token, "[redacted]")
	}
	return message
}

func (e tokenRedactedError) Unwrap() error { return e.err }

func redactTokens(err error, tokenSet map[string]struct{}) error {
	if err == nil || len(tokenSet) == 0 {
		return err
	}
	return tokenRedactedError{err: err, tokenSet: tokenSet}
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
	defer func() { _ = response.Body.Close() }()
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
	if (credential.Issuer != "" && credential.Issuer != s.issuer) || (credential.ClientID != "" && credential.ClientID != s.clientID) {
		return ErrCredentialScopeMismatch
	}
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
	if issuer.User != nil {
		return nil, errors.New("deviceauth: issuer URL must not contain userinfo")
	}
	if issuer.RawQuery != "" || issuer.Fragment != "" {
		return nil, errors.New("deviceauth: issuer URL must not contain a query or fragment")
	}
	if issuer.RawPath != "" {
		return nil, errors.New("deviceauth: issuer URL must not contain an encoded path")
	}
	issuer.Scheme = strings.ToLower(issuer.Scheme)
	hostname := strings.ToLower(issuer.Hostname())
	if hostname == "" {
		return nil, errors.New("deviceauth: issuer URL host is required")
	}
	if issuer.Scheme != "https" && (issuer.Scheme != "http" || !isLoopbackHost(hostname)) {
		return nil, errors.New("deviceauth: issuer must use https unless its host is loopback")
	}
	port := issuer.Port()
	if (issuer.Scheme == "https" && port == "443") || (issuer.Scheme == "http" && port == "80") {
		port = ""
	}
	if port == "" {
		if strings.Contains(hostname, ":") {
			issuer.Host = "[" + hostname + "]"
		} else {
			issuer.Host = hostname
		}
	} else {
		issuer.Host = net.JoinHostPort(hostname, port)
	}
	issuer.Path = strings.TrimRight(path.Clean(issuer.Path), "/")
	if issuer.Path == "." || issuer.Path == "/" {
		issuer.Path = ""
	}
	issuer.RawPath = ""
	return issuer, nil
}

func isLoopbackHost(host string) bool {
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
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

// ResponseError is a redacted non-success response from the authorization
// service. It deliberately excludes arbitrary response text, which may carry
// secrets or HTML from a proxy. OAuthError is populated only for a safe OAuth
// error code.
type ResponseError struct {
	Operation  string
	StatusCode int
	OAuthError string
}

func (e *ResponseError) Error() string {
	if e.OAuthError != "" {
		return fmt.Sprintf("deviceauth: %s request failed with HTTP %d (%s)", e.Operation, e.StatusCode, e.OAuthError)
	}
	return fmt.Sprintf("deviceauth: %s request failed with HTTP %d", e.Operation, e.StatusCode)
}

func responseError(operation string, response *http.Response) error {
	var payload struct {
		Error string `json:"error"`
	}
	_ = json.NewDecoder(io.LimitReader(response.Body, 4096)).Decode(&payload)
	return &ResponseError{
		Operation:  operation,
		StatusCode: response.StatusCode,
		OAuthError: safeOAuthErrorCode(payload.Error),
	}
}

func safeOAuthErrorCode(value string) string {
	switch value {
	case "invalid_request", "invalid_client", "invalid_grant", "unauthorized_client", "unsupported_grant_type", "invalid_scope", "authorization_pending", "slow_down", "access_denied", "expired_token":
		return value
	default:
		return ""
	}
}
