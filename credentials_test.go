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
	if _, err := NewKeyringStore("service", ""); err == nil {
		t.Fatal("NewKeyringStore() error = nil")
	}
	if _, err := newKeyringStore("", "host", &fakeCredentialKeyring{}); err == nil {
		t.Fatal("newKeyringStore() error = nil")
	}
	if _, err := newKeyringStore("service", "", &fakeCredentialKeyring{}); err == nil {
		t.Fatal("newKeyringStore() error = nil")
	}
	if _, err := newKeyringStore("service", "host", nil); err == nil {
		t.Fatal("newKeyringStore() error = nil")
	}
	if _, err := NewFileStore(""); err == nil {
		t.Fatal("NewFileStore() error = nil")
	}
}

func TestFileStoreErrorCases(t *testing.T) {
	dir := t.TempDir()

	// Save to an impossible path
	store, err := NewFileStore(filepath.Join(dir, "not-a-dir", "sub", "credential.json"))
	if err != nil {
		t.Fatal(err)
	}
	// Create a regular file where the directory needs to be
	if err := os.WriteFile(filepath.Join(dir, "not-a-dir"), []byte("file"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(Credential{AccessToken: "secret"}); err == nil {
		t.Error("expected Save to fail when directory cannot be created")
	}

	// Load non-json file
	corruptPath := filepath.Join(dir, "corrupt.json")
	if err := os.WriteFile(corruptPath, []byte("not-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	corruptStore, _ := NewFileStore(corruptPath)
	if _, err := corruptStore.Load(); err == nil {
		t.Error("expected Load to fail on non-json")
	}

	// Load file missing access token
	emptyTokenPath := filepath.Join(dir, "empty-token.json")
	if err := os.WriteFile(emptyTokenPath, []byte(`{"token_type":"Bearer"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	emptyTokenStore, _ := NewFileStore(emptyTokenPath)
	if _, err := emptyTokenStore.Load(); err == nil {
		t.Error("expected Load to fail when access token is missing")
	}

	// Load on a directory causes os.ReadFile to fail with read error
	dirAsPath := filepath.Join(dir, "is-a-dir")
	if err := os.MkdirAll(dirAsPath, 0o700); err != nil {
		t.Fatal(err)
	}
	dirReadStore, _ := NewFileStore(dirAsPath)
	if _, err := dirReadStore.Load(); err == nil {
		t.Error("expected Load to fail when path is a directory")
	}

	// Delete on a directory containing files causes os.Remove to fail
	nonEmptyDir := filepath.Join(dir, "non-empty-dir")
	if err := os.MkdirAll(nonEmptyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nonEmptyDir, "file"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	dirStore, _ := NewFileStore(nonEmptyDir)
	if err := dirStore.Delete(); err == nil {
		t.Error("expected Delete to fail on non-empty directory")
	}

	// Save fails when saveCredentialFile fails
	origSave := saveCredentialFile
	defer func() { saveCredentialFile = origSave }()
	saveCredentialFile = func(string, []byte) error { return errors.New("save fail") }
	dummyStore, _ := NewFileStore(filepath.Join(dir, "test.json"))
	if err := dummyStore.Save(Credential{AccessToken: "token"}); err == nil {
		t.Error("expected error when saveCredentialFile fails")
	}
	saveCredentialFile = origSave

	// Save fails when CreateTemp fails (parent is read-only)
	roDir := filepath.Join(dir, "ro-dir")
	if err := os.MkdirAll(roDir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(roDir, 0o700) }()
	roStore, _ := NewFileStore(filepath.Join(roDir, "credential.json"))
	if err := roStore.Save(Credential{AccessToken: "secret"}); err == nil {
		t.Error("expected Save to fail when parent dir is read-only")
	}

	// Save fails when Rename fails (target path is an existing directory)
	targetDir := filepath.Join(dir, "target-is-dir")
	if err := os.MkdirAll(targetDir, 0o700); err != nil {
		t.Fatal(err)
	}
	targetDirStore, _ := NewFileStore(targetDir)
	if err := targetDirStore.Save(Credential{AccessToken: "secret"}); err == nil {
		t.Error("expected Save to fail when target path is a directory")
	}
}

func TestNewKeyringStoreWithBackend(t *testing.T) {
	origBackend := defaultKeyringBackend
	defer func() { defaultKeyringBackend = origBackend }()

	fake := &fakeCredentialKeyring{values: make(map[string]string)}
	defaultKeyringBackend = fake

	store, err := NewKeyringStore("my-service", "my-account")
	if err != nil {
		t.Fatalf("NewKeyringStore failed: %v", err)
	}
	if err := store.Save(Credential{}); err == nil {
		t.Error("expected error when saving credential without access token")
	}
	if err := store.Save(Credential{AccessToken: "token123"}); err != nil {
		t.Fatalf("Save failed: %v", err)
	}
	cred, err := store.Load()
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if cred.AccessToken != "token123" {
		t.Fatalf("got %v, want token123", cred.AccessToken)
	}
}

func TestOperatingSystemKeyringDirect(t *testing.T) {
	osk := operatingSystemKeyring{}
	// Call Set (ignore result in case keyring is not configured on runner)
	_ = osk.Set("deviceauth-unit-test-never-used", "account", "val")
	// Call Get on nonexistent
	_, _ = osk.Get("deviceauth-unit-test-never-used", "account")
	// Call Delete on nonexistent
	_ = osk.Delete("deviceauth-unit-test-never-used", "account")
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
