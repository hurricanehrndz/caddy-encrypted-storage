//go:build darwin && cgo

package encryptedstorage

import (
	"context"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/mohammed90/caddy-encrypted-storage/internal/credstore"
)

func TestAgeKeychainProvisionHappyPath(t *testing.T) {
	dir := t.TempDir()

	// newStore returns a fresh store each time, since provisionFromCredentialStore
	// defers Close() on the store it receives.
	newStore := func() (credstore.Store, error) { return credstore.NewCustom(dir) }

	// Create a store for cleanup purposes.
	cleanupStore, err := credstore.NewCustom(dir)
	if err != nil {
		t.Fatalf("NewCustom for cleanup: %v", err)
	}
	t.Cleanup(func() { cleanupStore.Close() })

	ctx, _ := caddy.NewContext(caddy.Context{Context: context.Background()})

	// First provision: should bootstrap a new keypair.
	a1 := &Age{
		IdentitySource: "keychain",
		newStore:       newStore,
	}
	if err := a1.Provision(ctx); err != nil {
		t.Fatalf("first Provision (bootstrap): %v", err)
	}
	if a1.mk == nil {
		t.Fatal("mk should be non-nil after bootstrap")
	}
	if a1.Recipient == "" {
		t.Fatal("Recipient should be populated after bootstrap")
	}
	if !strings.HasPrefix(a1.Recipient, "age1") {
		t.Errorf("Recipient should start with age1, got %q", a1.Recipient)
	}

	// Clean up the bootstrapped credential.
	t.Cleanup(func() {
		_ = cleanupStore.Delete(credstore.ServiceName, a1.Recipient)
	})

	// Second provision: should reuse the existing identity.
	a2 := &Age{
		IdentitySource: "keychain",
		newStore:       newStore,
	}
	if err := a2.Provision(ctx); err != nil {
		t.Fatalf("second Provision (reuse): %v", err)
	}
	if a2.mk == nil {
		t.Fatal("mk should be non-nil after reuse")
	}
	if a2.Recipient != a1.Recipient {
		t.Errorf("Recipient should be stable across provisions: got %q, want %q",
			a2.Recipient, a1.Recipient)
	}
}
