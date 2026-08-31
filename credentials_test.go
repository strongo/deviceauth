package deviceauth

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	keyring "github.com/zalando/go-keyring"
)

func TestFileStoreRoundTripAndPermissions(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "nested", "credential.json")
	store, err := NewFileStore(path)
	if err != nil {
		t.Fatalf("NewFileStore() error = %v", err)
	}
	want := Credential{
		AccessToken: "secret",
		TokenType:   "Bearer",
		Expiry:      time.Unix(1234, 0).UTC(),
		AccountID:   "user-1",
		AccountName: "alex@example.com",
		Scopes:      []string{"account:read"},
	}
	if err := store.Save(want); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	got, err := store.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("credential = %#v, want %#v", got, want)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if gotMode := info.Mode().Perm(); gotMode != 0o600 {
		t.Fatalf("credential mode = %o, want 600", gotMode)
	}
	parentInfo, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatalf("Stat(parent) error = %v", err)
	}
	if gotMode := parentInfo.Mode().Perm(); gotMode != 0o700 {
		t.Fatalf("credential directory mode = %o, want 700", gotMode)
	}
	if err := store.Delete(); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	if _, err := store.Load(); !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("Load() after delete error = %v", err)
	}
	if err := store.Delete(); err != nil {
		t.Fatalf("second Delete() error = %v", err)
	}
}

func TestCredentialRequiresAccessToken(t *testing.T) {
	t.Parallel()

	store, err := NewFileStore(filepath.Join(t.TempDir(), "credential.json"))
	if err != nil {
		t.Fatalf("NewFileStore() error = %v", err)
	}
	if err := store.Save(Credential{}); err == nil {
		t.Fatal("Save() error = nil")
	}
}

func TestKeyringStoreRoundTripAndIdempotentDelete(t *testing.T) {
	t.Parallel()

	backend := &fakeCredentialKeyring{values: make(map[string]string)}
	store, err := newKeyringStore("test-cli", "cloud@example.com", backend)
	if err != nil {
		t.Fatal(err)
	}
	want := Credential{
		AccessToken: "secret",
		TokenType:   "Bearer",
		AccountID:   "user-1",
		Scopes:      []string{"account:read"},
	}
	if err := store.Save(want); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	got, err := store.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("credential = %#v, want %#v", got, want)
	}
	if err := store.Delete(); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	if _, err := store.Load(); !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("Load() after delete error = %v", err)
	}
	if err := store.Delete(); err != nil {
		t.Fatalf("second Delete() error = %v", err)
	}
}

func TestKeyringStoreWrapsBackendErrors(t *testing.T) {
	t.Parallel()

	backendErr := errors.New("backend unavailable")
	backend := &fakeCredentialKeyring{
		values:    make(map[string]string),
		setErr:    backendErr,
		getErr:    backendErr,
		deleteErr: backendErr,
	}
	store, err := newKeyringStore("test-cli", "cloud@example.com", backend)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(Credential{AccessToken: "secret"}); !errors.Is(err, backendErr) {
		t.Fatalf("Save() error = %v", err)
	}
	if _, err := store.Load(); !errors.Is(err, backendErr) {
		t.Fatalf("Load() error = %v", err)
	}
	if err := store.Delete(); !errors.Is(err, backendErr) {
		t.Fatalf("Delete() error = %v", err)
	}
}

func TestStoreConstructorsRejectEmptyIdentity(t *testing.T) {
	t.Parallel()

	if _, err := NewKeyringStore("", "host"); err == nil {
		t.Fatal("NewKeyringStore() error = nil")
	}
	if _, err := NewFileStore(""); err == nil {
		t.Fatal("NewFileStore() error = nil")
	}
}

type fakeCredentialKeyring struct {
	values    map[string]string
	setErr    error
	getErr    error
	deleteErr error
}

func (f *fakeCredentialKeyring) Set(service, account, value string) error {
	if f.setErr != nil {
		return f.setErr
	}
	f.values[service+"\x00"+account] = value
	return nil
}

func (f *fakeCredentialKeyring) Get(service, account string) (string, error) {
	if f.getErr != nil {
		return "", f.getErr
	}
	value, ok := f.values[service+"\x00"+account]
	if !ok {
		return "", keyring.ErrNotFound
	}
	return value, nil
}

func (f *fakeCredentialKeyring) Delete(service, account string) error {
	if f.deleteErr != nil {
		return f.deleteErr
	}
	key := service + "\x00" + account
	if _, ok := f.values[key]; !ok {
		return keyring.ErrNotFound
	}
	delete(f.values, key)
	return nil
}
