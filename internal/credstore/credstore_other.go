//go:build !darwin && !windows

package credstore

import "fmt"

// New returns an error on unsupported platforms.
func New() (Store, error) {
	return nil, fmt.Errorf(
		"identity_source 'keychain' is not supported on this platform; " +
			"supported platforms: macOS (darwin), Windows")
}

// NewCustom returns an error on unsupported platforms.
func NewCustom(_ string) (Store, error) {
	return nil, fmt.Errorf(
		"identity_source 'keychain' is not supported on this platform; " +
			"supported platforms: macOS (darwin), Windows")
}
