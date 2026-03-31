//go:build darwin && !cgo

package credstore

import "fmt"

// New returns an error when CGo is disabled on macOS.
func New(_ string) (Store, error) {
	return nil, fmt.Errorf(
		"identity_source 'keychain' requires CGo on macOS; " +
			"rebuild with CGO_ENABLED=1")
}
