//go:build windows

package credstore

import (
	"testing"
)

const testServiceName = "com.caddyserver.caddy.encrypted-storage.test"

func newTestStore(t *testing.T) Store {
	t.Helper()
	s, err := New("")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
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
