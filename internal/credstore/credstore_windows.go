//go:build windows

package credstore

import (
	"errors"
	"fmt"
	"strings"
	"syscall"

	"github.com/danieljoos/wincred"
)

// errNotFoundWin is the Windows ERROR_NOT_FOUND (1168) error code returned
// by the Credential Manager when a credential does not exist.
const errNotFoundWin = syscall.Errno(1168)

// windowsStore implements Store using the Windows Credential Manager.
type windowsStore struct{}

// New returns a Store backed by the Windows Credential Manager.
func New() (Store, error) {
	return &windowsStore{}, nil
}

// NewCustom returns a Store backed by the Windows Credential Manager.
// The storageRoot parameter is ignored on Windows (no custom keychain concept).
func NewCustom(_ string) (Store, error) {
	return &windowsStore{}, nil
}

// target builds the credential target name used in the Windows Credential
// Manager. The format is "<service>/<account>".
func target(service, account string) string {
	return service + "/" + account
}

// isNotFound reports whether err represents a Windows "not found" error.
func isNotFound(err error) bool {
	return errors.Is(err, errNotFoundWin)
}

// Get retrieves a credential from the Windows Credential Manager.
func (s *windowsStore) Get(service, account string) ([]byte, error) {
	cred, err := wincred.GetGenericCredential(target(service, account))
	if err != nil {
		if isNotFound(err) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("wincred get: %w", err)
	}
	return cred.CredentialBlob, nil
}

// GetFirst retrieves the first credential whose target starts with the given
// service name.
func (s *windowsStore) GetFirst(service string) (data []byte, account string, err error) {
	filter := service + "/*"
	creds, err := wincred.FilteredList(filter)
	if err != nil {
		if isNotFound(err) {
			return nil, "", ErrNotFound
		}
		return nil, "", fmt.Errorf("wincred filtered list: %w", err)
	}
	if len(creds) == 0 {
		return nil, "", ErrNotFound
	}

	first := creds[0]
	account = strings.TrimPrefix(first.TargetName, service+"/")
	return first.CredentialBlob, account, nil
}

// Set creates or updates a credential in the Windows Credential Manager.
func (s *windowsStore) Set(service, account string, data []byte) error {
	cred := wincred.NewGenericCredential(target(service, account))
	cred.UserName = "age-identity"
	cred.CredentialBlob = data
	cred.Persist = wincred.PersistLocalMachine
	if err := cred.Write(); err != nil {
		return fmt.Errorf("wincred write: %w", err)
	}
	return nil
}

// Delete removes a credential from the Windows Credential Manager.
func (s *windowsStore) Delete(service, account string) error {
	cred, err := wincred.GetGenericCredential(target(service, account))
	if err != nil {
		if isNotFound(err) {
			return ErrNotFound
		}
		return fmt.Errorf("wincred get for delete: %w", err)
	}
	if err := cred.Delete(); err != nil {
		return fmt.Errorf("wincred delete: %w", err)
	}
	return nil
}
