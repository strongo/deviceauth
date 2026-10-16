# deviceauth

`deviceauth` provides reusable OAuth 2.0 Device Authorization Grant UX and
credential storage for Go command-line applications.

It deliberately stays below product and command-framework concerns:

- RFC 8628 protocol behavior is delegated to `golang.org/x/oauth2`.
- browser launch is best-effort and always has a visible manual fallback;
- credentials use the operating system credential store by default;
- plaintext JSON storage is available only when a caller explicitly selects it;
- callers own product names, OAuth endpoints, client IDs, scopes, and commands.

```go
result, err := deviceauth.Login(ctx, deviceauth.LoginOptions{
	OAuthConfig: oauth2.Config{
		ClientID: "example-cli",
		Scopes:   []string{"account:read"},
		Endpoint: oauth2.Endpoint{
			DeviceAuthURL: "https://cloud.example.com/oauth/device/code",
			TokenURL:      "https://cloud.example.com/oauth/token",
		},
	},
	DeviceInfo: deviceauth.DeviceInfo{
		Name: "Alex's MacBook Pro", OS: "darwin", Arch: "arm64", ClientVersion: "1.2.3",
	},
	OpenBrowser: deviceauth.OpenBrowser,
	Output:      os.Stdout,
	ErrorOutput: os.Stderr,
})
```

`DeviceInfo` is sent as optional device-authorization request parameters so a
server can identify the requesting device during consent. It is informational,
untrusted metadata; authorization state and timestamps remain server-owned.

The module is MIT licensed.

## Moving an authorization service to a new host

`Client` binds every saved credential to its `Issuer`. When a service moves,
configure the new base URL as `Issuer` and list the old one in both:

- `PreviousIssuers`: a stored credential bound to an old issuer loads as
  `*IssuerMovedError` (it matches `ErrCredentialIssuerMoved` and
  `ErrCredentialScopeMismatch`). `DeviceLoginAndStore` prints one notice line
  (`DeviceLoginOptions.IssuerMovedNotice`, or `DefaultIssuerMovedNotice`),
  runs a fresh login and revokes the old grant at the new issuer; `Logout`
  revokes it there too. `NewKeyringStore` also looks under the old issuer's
  keyring identity, and `NewMigratingStore` does the same for other stores.
- `FallbackIssuers`: lets a client ship before the new host serves. Until
  `Issuer` has answered once, a transport failure (DNS, connection, TLS) or
  HTTP 404 retries the request at the next fallback; the first base URL that
  answers serves the rest of the `Client`'s lifetime. Credentials stay bound
  to `Issuer`. Configure fallbacks only for a default production issuer, never
  for an operator override, and remove them once the move is complete.
