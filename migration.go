package deviceauth

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

// ErrCredentialIssuerMoved reports a stored credential that was issued while
// the authorization service still answered at one of the Client's
// PreviousIssuers. errors.Is also matches ErrCredentialScopeMismatch, because
// such a credential is never a session for the current issuer.
var ErrCredentialIssuerMoved = errors.New("deviceauth: credential was saved for a previous issuer")

// IssuerMovedError is returned by a Client's scoped store when the stored
// credential is bound to one of the Client's PreviousIssuers. Credential holds
// the stored value so a caller can revoke it at the current issuer; Error never
// includes token material.
type IssuerMovedError struct {
	PreviousIssuer string
	Issuer         string
	Credential     Credential
}

func (e *IssuerMovedError) Error() string {
	return fmt.Sprintf("deviceauth: sign-in moved from %s to %s; sign in again", e.PreviousIssuer, e.Issuer)
}

// Is lets errors.Is match both ErrCredentialIssuerMoved and the more general
// ErrCredentialScopeMismatch.
func (e *IssuerMovedError) Is(target error) bool {
	return target == ErrCredentialIssuerMoved || target == ErrCredentialScopeMismatch
}

// DefaultIssuerMovedNotice is the line DeviceLoginAndStore writes to
// ErrorOutput when it replaces a credential bound to a previous issuer and the
// caller set no DeviceLoginOptions.IssuerMovedNotice.
func DefaultIssuerMovedNotice(moved *IssuerMovedError) string {
	return fmt.Sprintf("Sign-in moved from %s to %s; starting a fresh sign-in.", hostOf(moved.PreviousIssuer), hostOf(moved.Issuer))
}

func hostOf(issuer string) string {
	parsed, err := url.Parse(issuer)
	if err != nil || parsed.Host == "" {
		return issuer
	}
	return parsed.Host
}

func parseIssuers(field string, primary *url.URL, rawIssuers []string) ([]*url.URL, error) {
	issuers := make([]*url.URL, 0, len(rawIssuers))
	seen := map[string]struct{}{primary.String(): {}}
	for _, raw := range compactStrings(rawIssuers) {
		issuer, err := parseIssuer(raw)
		if err != nil {
			return nil, fmt.Errorf("deviceauth: %s: %w", field, err)
		}
		if _, exists := seen[issuer.String()]; exists {
			continue
		}
		seen[issuer.String()] = struct{}{}
		issuers = append(issuers, issuer)
	}
	return issuers, nil
}

func issuerStrings(issuers []*url.URL) []string {
	values := make([]string, 0, len(issuers))
	for _, issuer := range issuers {
		values = append(values, issuer.String())
	}
	return values
}

// NewMigratingStore returns a store that reads current first and, only when
// current holds no credential, the first credential found in previous. Wrap
// it in Client.ScopedStore: a credential found in a previous location that is
// bound to one of the Client's PreviousIssuers then loads as
// *IssuerMovedError. A successful Save, and Delete, also remove the
// credentials in previous so a moved credential is reported at most until the
// next login or logout. Errors reading a previous location are ignored: they
// must never block a fresh login.
func NewMigratingStore(current Store, previous ...Store) Store {
	return migratingStore{current: current, previous: previous}
}

type migratingStore struct {
	current  Store
	previous []Store
}

func (s migratingStore) Load() (Credential, error) {
	credential, err := s.current.Load()
	if !errors.Is(err, ErrCredentialNotFound) {
		return credential, err
	}
	for _, store := range s.previous {
		if credential, previousErr := store.Load(); previousErr == nil {
			return credential, nil
		}
	}
	return Credential{}, err
}

func (s migratingStore) Save(credential Credential) error {
	if err := s.current.Save(credential); err != nil {
		return err
	}
	for _, store := range s.previous {
		_ = store.Delete()
	}
	return nil
}

func (s migratingStore) Delete() error {
	errs := []error{s.current.Delete()}
	for _, store := range s.previous {
		errs = append(errs, store.Delete())
	}
	return errors.Join(errs...)
}

// issuerRouter decides, once per Client, which base URL serves requests that
// were built for the primary issuer. Until the primary has answered, a
// transport error or HTTP 404 from it moves the request to the next fallback.
// The first base URL that answers with anything else is used for every later
// request, so a device code is always polled where it was issued.
type issuerRouter struct {
	primary   *url.URL
	fallbacks []*url.URL

	mu     sync.Mutex
	chosen *url.URL
	probe  chan struct{}
}

// acquireProbe serializes requests until a serving issuer is selected. A
// waiter can abandon the selection promptly when its context is cancelled.
func (r *issuerRouter) acquireProbe(ctx context.Context) (func(), error) {
	r.mu.Lock()
	if r.chosen != nil {
		r.mu.Unlock()
		return func() {}, nil
	}
	if r.probe == nil {
		r.probe = make(chan struct{}, 1)
	}
	probe := r.probe
	r.mu.Unlock()
	select {
	case probe <- struct{}{}:
		return func() { <-probe }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (r *issuerRouter) candidates() []*url.URL {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.chosen != nil {
		return []*url.URL{r.chosen}
	}
	return append([]*url.URL{r.primary}, r.fallbacks...)
}

func (r *issuerRouter) choose(base *url.URL) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.chosen == nil {
		r.chosen = base
	}
}

// serving returns the base URL that answered for this Client, or "" before
// any request was decided.
func (r *issuerRouter) serving() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.chosen == nil {
		return ""
	}
	return r.chosen.String()
}

func (r *issuerRouter) routes(u *url.URL) bool {
	return strings.EqualFold(u.Scheme, r.primary.Scheme) && strings.EqualFold(u.Host, r.primary.Host) &&
		(u.Path == r.primary.Path || strings.HasPrefix(u.Path, r.primary.Path+"/"))
}

func (r *issuerRouter) rebase(u *url.URL, base *url.URL) *url.URL {
	rebased := *u
	rebased.Scheme = base.Scheme
	rebased.Host = base.Host
	rebased.Path = base.Path + strings.TrimPrefix(u.Path, r.primary.Path)
	rebased.RawPath = ""
	return &rebased
}

type fallbackTransport struct {
	base   http.RoundTripper
	router *issuerRouter
}

func (t fallbackTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if !t.router.routes(req.URL) {
		return t.base.RoundTrip(req)
	}
	release, err := t.router.acquireProbe(req.Context())
	if err != nil {
		return nil, err
	}
	defer release()
	var body []byte
	if req.Body != nil {
		var err error
		body, err = io.ReadAll(req.Body)
		_ = req.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("deviceauth: read request body: %w", err)
		}
	}
	var firstResponse *http.Response
	var firstErr error
	for i, base := range t.router.candidates() {
		attempt := req.Clone(req.Context())
		attempt.URL = t.router.rebase(req.URL, base)
		attempt.Host = ""
		if req.Body != nil {
			attempt.Body = io.NopCloser(bytes.NewReader(body))
			attempt.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
			attempt.ContentLength = int64(len(body))
		}
		response, err := t.base.RoundTrip(attempt)
		if err != nil && req.Context().Err() != nil {
			if firstResponse != nil {
				_ = firstResponse.Body.Close()
			}
			return response, err
		}
		if !notServing(req.Context(), response, err) {
			t.router.choose(base)
			if firstResponse != nil {
				_ = firstResponse.Body.Close()
			}
			return response, err
		}
		if i == 0 {
			firstResponse, firstErr = response, err
		} else if response != nil {
			_ = response.Body.Close()
		}
	}
	return firstResponse, firstErr
}

// notServing reports a base URL that is not answering for the authorization
// service yet: no response at all (DNS, connection, or TLS failure) or 404.
// A caller's own cancellation is never treated as a reason to fall back.
func notServing(ctx context.Context, response *http.Response, err error) bool {
	if err != nil {
		return ctx.Err() == nil
	}
	return response.StatusCode == http.StatusNotFound
}

// httpClient returns the HTTP client for a request to this Client's issuer.
// Without fallbacks it is the caller's client from ctx unchanged.
func (c *Client) httpClient(ctx context.Context) *http.Client {
	base := httpClient(ctx)
	if c.router == nil {
		return base
	}
	transport := base.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	return &http.Client{
		Transport:     fallbackTransport{base: transport, router: c.router},
		CheckRedirect: base.CheckRedirect,
		Jar:           base.Jar,
		Timeout:       base.Timeout,
	}
}

// ServingIssuer returns the base URL that actually answered for this Client:
// the configured Issuer, or one of FallbackIssuers while Issuer is not serving
// yet. It returns Issuer before any request was made. Stored credentials are
// always bound to Issuer regardless of which base URL served them.
func (c *Client) ServingIssuer() string {
	if c.router != nil {
		if serving := c.router.serving(); serving != "" {
			return serving
		}
	}
	return c.Issuer()
}

// PreviousIssuers returns the canonical previous issuers configured for this
// client.
func (c *Client) PreviousIssuers() []string {
	return append([]string(nil), c.previousIssuers...)
}
