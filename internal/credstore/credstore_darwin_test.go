//go:build darwin && cgo

package credstore

import (
	"os"
	"path/filepath"
	"testing"
)

const testServiceName = "com.caddyserver.caddy.encrypted-storage.test"

func newTestStore(t *testing.T) Store {
	t.Helper()
	dir := t.TempDir()
	s, err := NewCustom(dir)
	if err != nil {
		t.Fatalf("NewCustom: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestNewUsesDefaultKeychain(t *testing.T) {
	s, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ds := s.(*darwinStore)
	if ds.useCustomKeychain() {
		t.Error("New() should use the default keychain, not a custom one")
	}
}

func TestNewCreatesKeychainFiles(t *testing.T) {
	dir := t.TempDir()
	s, err := NewCustom(dir)
	if err != nil {
		t.Fatalf("NewCustom: %v", err)
	}
	t.Cleanup(func() { s.Close() })

	kcDir := filepath.Join(dir, keychainDir)
	if _, err := os.Stat(filepath.Join(kcDir, passwordFile)); err != nil {
		t.Errorf("password file should exist: %v", err)
	}
	if _, err := os.Stat(filepath.Join(kcDir, keychainFile)); err != nil {
		t.Errorf("keychain file should exist: %v", err)
	}
}

func TestNewReopensExistingKeychain(t *testing.T) {
	dir := t.TempDir()
	s1, err := NewCustom(dir)
	if err != nil {
		t.Fatalf("NewCustom (first): %v", err)
	}
	t.Cleanup(func() { s1.(*darwinStore).Close() })

	account := "age1reopentest0000000000000000000000000000000000000000000000000"
	data := []byte("AGE-SECRET-KEY-REOPEN00000000000000000000000000000000000000000000000000000")
	if err := s1.Set(testServiceName, account, data); err != nil {
		t.Fatalf("Set: %v", err)
	}

	// Open a second store against the same directory.
	s2, err := NewCustom(dir)
	if err != nil {
		t.Fatalf("NewCustom (second): %v", err)
	}
	t.Cleanup(func() { s2.(*darwinStore).Close() })

	got, err := s2.Get(testServiceName, account)
	if err != nil {
		t.Fatalf("Get from reopened store: %v", err)
	}
	if string(got) != string(data) {
		t.Errorf("Get: got %q, want %q", got, data)
	}

	t.Cleanup(func() { _ = s2.Delete(testServiceName, account) })
}

func TestSetCreatesRestrictedACL(t *testing.T) {
	dir := t.TempDir()
	s, err := NewCustom(dir)
	if err != nil {
		t.Fatalf("NewCustom: %v", err)
	}
	ds := s.(*darwinStore)
	t.Cleanup(func() { ds.Close() })

	account := "age1acltest00000000000000000000000000000000000000000000000000"
	data := []byte("AGE-SECRET-KEY-ACLTEST00000000000000000000000000000000000000000000000000")

	t.Cleanup(func() {
		_ = s.Delete(testServiceName, account)
	})

	if err := s.Set(testServiceName, account, data); err != nil {
		t.Fatalf("Set: %v", err)
	}

	// Verify the item has a non-empty trusted app list on ACLAuthorizationDecrypt,
	// meaning only specific applications (self) can access it.
	hasTrustedApps, err := ds.HasTrustedAppACL(testServiceName, account)
	if err != nil {
		t.Fatalf("HasTrustedAppACL: %v", err)
	}
	if !hasTrustedApps {
		t.Error("keychain item should have a non-empty trusted application list on its decrypt ACL")
	}
}

func TestSetAndGet(t *testing.T) {
	s := newTestStore(t)
	account := "age1testaccount000000000000000000000000000000000000000000000000"
	data := []byte("AGE-SECRET-KEY-TESTDATA000000000000000000000000000000000000000000000000000")

	t.Cleanup(func() {
		_ = s.Delete(testServiceName, account)
	})

	if err := s.Set(testServiceName, account, data); err != nil {
		t.Fatalf("Set: %v", err)
	}

	got, err := s.Get(testServiceName, account)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != string(data) {
		t.Errorf("Get: got %q, want %q", got, data)
	}
}

func TestGetNotFound(t *testing.T) {
	s := newTestStore(t)
	_, err := s.Get(testServiceName, "nonexistent-account")
	if err == nil {
		t.Fatal("expected ErrNotFound")
	}
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound, got: %v", err)
	}
}

func TestSetOverwrite(t *testing.T) {
	s := newTestStore(t)
	account := "age1overwritetest0000000000000000000000000000000000000000000000"
	data1 := []byte("AGE-SECRET-KEY-FIRST0000000000000000000000000000000000000000000000000000")
	data2 := []byte("AGE-SECRET-KEY-SECOND000000000000000000000000000000000000000000000000000")

	t.Cleanup(func() {
		_ = s.Delete(testServiceName, account)
	})

	if err := s.Set(testServiceName, account, data1); err != nil {
		t.Fatalf("Set first: %v", err)
	}
	if err := s.Set(testServiceName, account, data2); err != nil {
		t.Fatalf("Set second: %v", err)
	}

	got, err := s.Get(testServiceName, account)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != string(data2) {
		t.Errorf("Get after overwrite: got %q, want %q", got, data2)
	}
}

func TestGetFirst(t *testing.T) {
	s := newTestStore(t)
	account := "age1getfirsttest00000000000000000000000000000000000000000000000"
	data := []byte("AGE-SECRET-KEY-GETFIRST0000000000000000000000000000000000000000000000000")

	t.Cleanup(func() {
		_ = s.Delete(testServiceName, account)
	})

	if err := s.Set(testServiceName, account, data); err != nil {
		t.Fatalf("Set: %v", err)
	}

	got, gotAccount, err := s.GetFirst(testServiceName)
	if err != nil {
		t.Fatalf("GetFirst: %v", err)
	}
	if string(got) != string(data) {
		t.Errorf("GetFirst data: got %q, want %q", got, data)
	}
	if gotAccount != account {
		t.Errorf("GetFirst account: got %q, want %q", gotAccount, account)
	}
}

func TestGetFirstNotFound(t *testing.T) {
	s := newTestStore(t)
	_, _, err := s.GetFirst(testServiceName + ".empty")
	if err == nil {
		t.Fatal("expected ErrNotFound")
	}
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound, got: %v", err)
	}
}

func TestDelete(t *testing.T) {
	s := newTestStore(t)
	account := "age1deletetest000000000000000000000000000000000000000000000000"
	data := []byte("AGE-SECRET-KEY-DELETE00000000000000000000000000000000000000000000000000000")

	if err := s.Set(testServiceName, account, data); err != nil {
		t.Fatalf("Set: %v", err)
	}

	if err := s.Delete(testServiceName, account); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	_, err := s.Get(testServiceName, account)
	if err != ErrNotFound {
		t.Errorf("Get after Delete: expected ErrNotFound, got: %v", err)
	}
}

func TestDeleteNotFound(t *testing.T) {
	s := newTestStore(t)
	err := s.Delete(testServiceName, "nonexistent-delete-account")
	if err == nil {
		t.Fatal("expected ErrNotFound")
	}
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound, got: %v", err)
	}
}
