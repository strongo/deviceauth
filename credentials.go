package deviceauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	keyring "github.com/zalando/go-keyring"
)

// ErrCredentialNotFound reports that no credential exists for a configured
// service/account pair.
var ErrCredentialNotFound = errors.New("deviceauth: credential not found")

// Credential is the persisted result of a device authorization.
type Credential struct {
	AccessToken  string    `json:"access_token"`
	TokenType    string    `json:"token_type,omitempty"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	Expiry       time.Time `json:"expiry,omitempty"`
	// Issuer and ClientID bind a persisted credential to the authorization
	// service and public OAuth client that issued it. They are set by a
	// Client's ScopedStore; the fields remain optional for backwards
	// compatibility with credentials saved by older callers.
	Issuer      string   `json:"issuer,omitempty"`
	ClientID    string   `json:"client_id,omitempty"`
	AccountID   string   `json:"account_id,omitempty"`
	AccountName string   `json:"account_name,omitempty"`
	Scopes      []string `json:"scopes,omitempty"`
}

// Store persists and removes one credential selected by the concrete store's
// service/account configuration.
type Store interface {
	Save(Credential) error
	Load() (Credential, error)
	Delete() error
}

// KeyringStore keeps a credential in the operating system credential store.
type KeyringStore struct {
	service string
	account string
	backend credentialKeyring
}

type credentialKeyring interface {
	Set(service, account, value string) error
	Get(service, account string) (string, error)
	Delete(service, account string) error
}

type operatingSystemKeyring struct{}

func (operatingSystemKeyring) Set(service, account, value string) error {
	return keyring.Set(service, account, value)
}

func (operatingSystemKeyring) Get(service, account string) (string, error) {
	return keyring.Get(service, account)
}

func (operatingSystemKeyring) Delete(service, account string) error {
	return keyring.Delete(service, account)
}

var defaultKeyringBackend credentialKeyring = operatingSystemKeyring{}

// NewKeyringStore returns a secure credential store. service should identify
// the CLI and account should normally identify the authorization host.
func NewKeyringStore(service, account string) (*KeyringStore, error) {
	if service == "" || account == "" {
		return nil, errors.New("deviceauth: keyring service and account are required")
	}
	return newKeyringStore(service, account, defaultKeyringBackend)
}

func newKeyringStore(service, account string, backend credentialKeyring) (*KeyringStore, error) {
	if service == "" || account == "" || backend == nil {
		return nil, errors.New("deviceauth: keyring service, account, and backend are required")
	}
	return &KeyringStore{service: service, account: account, backend: backend}, nil
}

// Save stores credential as one JSON value in the operating system keyring.
func (s *KeyringStore) Save(credential Credential) error {
	encoded, err := encodeCredential(credential)
	if err != nil {
		return err
	}
	if err := s.backend.Set(s.service, s.account, string(encoded)); err != nil {
		return fmt.Errorf("save credential in operating system keyring: %w", err)
	}
	return nil
}

// Load reads and validates the credential in the operating system keyring.
func (s *KeyringStore) Load() (Credential, error) {
	encoded, err := s.backend.Get(s.service, s.account)
	if errors.Is(err, keyring.ErrNotFound) {
		return Credential{}, ErrCredentialNotFound
	}
	if err != nil {
		return Credential{}, fmt.Errorf("load credential from operating system keyring: %w", err)
	}
	return decodeCredential([]byte(encoded))
}

// Delete removes the credential. Deleting an absent credential succeeds.
func (s *KeyringStore) Delete() error {
	err := s.backend.Delete(s.service, s.account)
	if err == nil || errors.Is(err, keyring.ErrNotFound) {
		return nil
	}
	return fmt.Errorf("delete credential from operating system keyring: %w", err)
}

// FileStore is an explicitly insecure 0600 JSON credential store. It is
// provided for headless environments only; callers should require a user flag
// before selecting it.
type FileStore struct {
	path string
}

// NewFileStore returns a plaintext store at path.
func NewFileStore(path string) (*FileStore, error) {
	if path == "" {
		return nil, errors.New("deviceauth: credential file path is required")
	}
	return &FileStore{path: path}, nil
}

// Save atomically writes a credential with directory mode 0700 and file mode
// 0600. The token remains plaintext and must be treated as sensitive.
func (s *FileStore) Save(credential Credential) error {
	encoded, err := encodeCredential(credential)
	if err != nil {
		return err
	}
	return saveCredentialFile(s.path, encoded)
}

var saveCredentialFile = func(path string, encoded []byte) error {
	parent := filepath.Dir(path)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return fmt.Errorf("create credential directory: %w", err)
	}
	temp, err := os.CreateTemp(parent, ".deviceauth-credential-*")
	if err != nil {
		return fmt.Errorf("create temporary credential file: %w", err)
	}
	tempPath := temp.Name()
	defer func() { _ = os.Remove(tempPath) }()
	_, _ = temp.Write(encoded)
	_ = temp.Close()
	if err := os.Rename(tempPath, path); err != nil {
		return fmt.Errorf("replace credential file: %w", err)
	}
	return nil
}

// Load reads and validates the plaintext credential file.
func (s *FileStore) Load() (Credential, error) {
	encoded, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return Credential{}, ErrCredentialNotFound
	}
	if err != nil {
		return Credential{}, fmt.Errorf("read credential file: %w", err)
	}
	return decodeCredential(encoded)
}

// Delete removes the plaintext credential file. Absence succeeds.
func (s *FileStore) Delete() error {
	err := os.Remove(s.path)
	if err == nil || errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return fmt.Errorf("delete credential file: %w", err)
}

func encodeCredential(credential Credential) ([]byte, error) {
	if credential.AccessToken == "" {
		return nil, errors.New("deviceauth: access token is required")
	}
	encoded, _ := json.MarshalIndent(credential, "", "  ")
	return append(encoded, '\n'), nil
}

func decodeCredential(encoded []byte) (Credential, error) {
	var credential Credential
	if err := json.Unmarshal(encoded, &credential); err != nil {
		return Credential{}, fmt.Errorf("decode credential: %w", err)
	}
	if credential.AccessToken == "" {
		return Credential{}, errors.New("decode credential: access token is missing")
	}
	return credential, nil
}
