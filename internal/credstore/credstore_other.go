//go:build !darwin && !windows

package credstore

import "fmt"

// New returns an error on unsupported platforms.
func New(_ string) (Store, error) {
	return nil, fmt.Errorf(
		"identity_source 'keychain' is not supported on this platform; " +
			"supported platforms: macOS (darwin), Windows")
}
