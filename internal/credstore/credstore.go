package credstore

import "errors"

// ServiceName is the identifier used to scope credential store entries
// to this Caddy module.
const ServiceName = "com.caddyserver.caddy.encrypted-storage"

// ErrNotFound is returned when a credential does not exist in the store.
var ErrNotFound = errors.New("credential not found")

// Store provides platform-independent credential storage operations.
// Implementations may hold OS resources; callers should defer Close()
// after obtaining a Store.
type Store interface {
	// Get retrieves a credential by service and account names.
	// Returns ErrNotFound if the credential does not exist.
	Get(service, account string) ([]byte, error)

	// GetFirst retrieves the first credential matching the service name.
	// Returns the data, the account name, and any error.
	// Returns ErrNotFound if no credentials exist for the service.
	GetFirst(service string) (data []byte, account string, err error)

	// Set creates or updates a credential identified by service and account.
	Set(service, account string, data []byte) error

	// Delete removes a credential by service and account names.
	// Returns ErrNotFound if the credential does not exist.
	Delete(service, account string) error

	// Close releases any OS resources held by the store.
	// It is safe to call multiple times.
	Close() error
}
