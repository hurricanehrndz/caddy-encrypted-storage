//go:build darwin && cgo

package credstore

/*
#cgo LDFLAGS: -framework CoreFoundation -framework Security
#cgo CFLAGS: -Wno-deprecated-declarations
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
*/
import "C"

import (
	"fmt"
	"unsafe"
)

// buildTimeTeamID can be set at build time via:
//
//	-ldflags "-X github.com/mohammed90/caddy-encrypted-storage/internal/credstore.buildTimeTeamID=SBSSF9BESA"
var buildTimeTeamID string

// darwinStore implements Store using the macOS Keychain via Security Framework.
type darwinStore struct {
	teamID string
}

// New creates a new macOS Keychain-backed credential store. The build-time
// buildTimeTeamID takes precedence over the runtimeTeamID argument. At least
// one must be non-empty.
func New(runtimeTeamID string) (Store, error) {
	tid := buildTimeTeamID
	if tid == "" {
		tid = runtimeTeamID
	}
	if tid == "" {
		return nil, fmt.Errorf("team_id is required on macOS for keychain ACL (set via build-time ldflags or Caddyfile team_id directive)")
	}
	return &darwinStore{teamID: tid}, nil
}

// ---------------------------------------------------------------------------
// CoreFoundation helpers
// ---------------------------------------------------------------------------

// cfString creates a CFStringRef from a Go string. The caller must release
// the returned reference with C.CFRelease.
func cfString(s string) C.CFStringRef {
	cs := C.CString(s)
	defer C.free(unsafe.Pointer(cs))
	return C.CFStringCreateWithCString(C.kCFAllocatorDefault, cs, C.kCFStringEncodingUTF8)
}

// cfData creates a CFDataRef from a Go byte slice. The caller must release
// the returned reference with C.CFRelease.
func cfData(b []byte) C.CFDataRef {
	if len(b) == 0 {
		return C.CFDataCreate(C.kCFAllocatorDefault, nil, 0)
	}
	return C.CFDataCreate(C.kCFAllocatorDefault, (*C.UInt8)(unsafe.Pointer(&b[0])), C.CFIndex(len(b)))
}

// cfDictionary builds an immutable CFDictionary from parallel slices of keys
// and values. The caller must release the returned reference with C.CFRelease.
func cfDictionary(keys []C.CFTypeRef, values []C.CFTypeRef) C.CFDictionaryRef {
	return C.CFDictionaryCreate(
		C.kCFAllocatorDefault,
		(*unsafe.Pointer)(unsafe.Pointer(&keys[0])),
		(*unsafe.Pointer)(unsafe.Pointer(&values[0])),
		C.CFIndex(len(keys)),
		&C.kCFTypeDictionaryKeyCallBacks,
		&C.kCFTypeDictionaryValueCallBacks,
	)
}

// goBytes converts a CFDataRef to a Go byte slice. Returns nil if ref is 0.
func goBytes(ref C.CFDataRef) []byte {
	if ref == 0 {
		return nil
	}
	length := C.CFDataGetLength(ref)
	if length == 0 {
		return []byte{}
	}
	ptr := C.CFDataGetBytePtr(ref)
	return C.GoBytes(unsafe.Pointer(ptr), C.int(length))
}

// goStringFromCF converts a CFStringRef to a Go string. Returns "" if ref is 0.
func goStringFromCF(ref C.CFStringRef) string {
	if ref == 0 {
		return ""
	}
	// Try the fast path first.
	cstr := C.CFStringGetCStringPtr(ref, C.kCFStringEncodingUTF8)
	if cstr != nil {
		return C.GoString(cstr)
	}
	// Fallback: copy into a buffer.
	length := C.CFStringGetLength(ref)
	maxSize := C.CFStringGetMaximumSizeForEncoding(length, C.kCFStringEncodingUTF8) + 1
	buf := C.malloc(C.size_t(maxSize))
	defer C.free(buf)
	if C.CFStringGetCString(ref, (*C.char)(buf), maxSize, C.kCFStringEncodingUTF8) == C.Boolean(0) {
		return ""
	}
	return C.GoString((*C.char)(buf))
}

// ---------------------------------------------------------------------------
// SecAccess helper
// ---------------------------------------------------------------------------

// createAccess builds a SecAccessRef that restricts keychain item access to
// the current application (self) and applications signed with the given team
// identifier.
func (s *darwinStore) createAccess(description string) (C.SecAccessRef, error) {
	// Create a trusted-application reference for "self" (NULL path = calling app).
	var selfApp C.SecTrustedApplicationRef
	status := C.SecTrustedApplicationCreateFromPath(nil, &selfApp)
	if status != C.errSecSuccess {
		return 0, fmt.Errorf("SecTrustedApplicationCreateFromPath failed: OSStatus %d", status)
	}
	defer C.CFRelease(C.CFTypeRef(selfApp))

	// Build a CFArray containing only self.
	apps := []C.CFTypeRef{C.CFTypeRef(selfApp)}
	trustedApps := C.CFArrayCreate(
		C.kCFAllocatorDefault,
		(*unsafe.Pointer)(unsafe.Pointer(&apps[0])),
		C.CFIndex(len(apps)),
		&C.kCFTypeArrayCallBacks,
	)
	defer C.CFRelease(C.CFTypeRef(trustedApps))

	descCF := cfString(description)
	defer C.CFRelease(C.CFTypeRef(descCF))

	var access C.SecAccessRef
	status = C.SecAccessCreate(descCF, trustedApps, &access)
	if status != C.errSecSuccess {
		return 0, fmt.Errorf("SecAccessCreate failed: OSStatus %d", status)
	}
	return access, nil
}

// ---------------------------------------------------------------------------
// Store interface implementation
// ---------------------------------------------------------------------------

// Get retrieves the credential data for the given service and account.
// Returns ErrNotFound if the item does not exist.
func (s *darwinStore) Get(service, account string) ([]byte, error) {
	serviceCF := cfString(service)
	defer C.CFRelease(C.CFTypeRef(serviceCF))

	accountCF := cfString(account)
	defer C.CFRelease(C.CFTypeRef(accountCF))

	keys := []C.CFTypeRef{
		C.CFTypeRef(C.kSecClass),
		C.CFTypeRef(C.kSecAttrService),
		C.CFTypeRef(C.kSecAttrAccount),
		C.CFTypeRef(C.kSecReturnData),
		C.CFTypeRef(C.kSecMatchLimit),
	}
	values := []C.CFTypeRef{
		C.CFTypeRef(C.kSecClassGenericPassword),
		C.CFTypeRef(serviceCF),
		C.CFTypeRef(accountCF),
		C.CFTypeRef(C.kCFBooleanTrue),
		C.CFTypeRef(C.kSecMatchLimitOne),
	}

	query := cfDictionary(keys, values)
	defer C.CFRelease(C.CFTypeRef(query))

	var result C.CFTypeRef
	status := C.SecItemCopyMatching(query, &result)
	if status == C.errSecItemNotFound {
		return nil, ErrNotFound
	}
	if status != C.errSecSuccess {
		return nil, fmt.Errorf("SecItemCopyMatching failed: OSStatus %d", status)
	}
	defer C.CFRelease(result)

	data := goBytes(C.CFDataRef(result))
	return data, nil
}

// GetFirst retrieves the first credential matching the given service name.
// It returns the credential data, the associated account name, and any error.
// Returns ErrNotFound if no credentials exist for the service.
func (s *darwinStore) GetFirst(service string) (data []byte, account string, err error) {
	serviceCF := cfString(service)
	defer C.CFRelease(C.CFTypeRef(serviceCF))

	keys := []C.CFTypeRef{
		C.CFTypeRef(C.kSecClass),
		C.CFTypeRef(C.kSecAttrService),
		C.CFTypeRef(C.kSecMatchLimit),
		C.CFTypeRef(C.kSecReturnData),
		C.CFTypeRef(C.kSecReturnAttributes),
	}
	values := []C.CFTypeRef{
		C.CFTypeRef(C.kSecClassGenericPassword),
		C.CFTypeRef(serviceCF),
		C.CFTypeRef(C.kSecMatchLimitOne),
		C.CFTypeRef(C.kCFBooleanTrue),
		C.CFTypeRef(C.kCFBooleanTrue),
	}

	query := cfDictionary(keys, values)
	defer C.CFRelease(C.CFTypeRef(query))

	var result C.CFTypeRef
	status := C.SecItemCopyMatching(query, &result)
	if status == C.errSecItemNotFound {
		return nil, "", ErrNotFound
	}
	if status != C.errSecSuccess {
		return nil, "", fmt.Errorf("SecItemCopyMatching failed: OSStatus %d", status)
	}
	defer C.CFRelease(result)

	// The result is a CFDictionary containing both attributes and data.
	dict := C.CFDictionaryRef(result)

	// Extract the credential data.
	dataPtr := C.CFDictionaryGetValue(dict, unsafe.Pointer(C.kSecValueData))
	if dataPtr == nil {
		return nil, "", fmt.Errorf("keychain item missing value data")
	}
	data = goBytes(C.CFDataRef(dataPtr))

	// Extract the account name from the attributes.
	accountPtr := C.CFDictionaryGetValue(dict, unsafe.Pointer(C.kSecAttrAccount))
	if accountPtr == nil {
		return nil, "", fmt.Errorf("keychain item missing account attribute")
	}
	account = goStringFromCF(C.CFStringRef(accountPtr))

	return data, account, nil
}

// Set creates or updates a keychain item for the given service and account.
// If the item already exists, its data is updated. Otherwise a new item is
// created with access control restricting use to self and applications signed
// with the configured team ID.
func (s *darwinStore) Set(service, account string, data []byte) error {
	serviceCF := cfString(service)
	defer C.CFRelease(C.CFTypeRef(serviceCF))

	accountCF := cfString(account)
	defer C.CFRelease(C.CFTypeRef(accountCF))

	dataCF := cfData(data)
	defer C.CFRelease(C.CFTypeRef(dataCF))

	// Build a query to check whether the item already exists.
	queryKeys := []C.CFTypeRef{
		C.CFTypeRef(C.kSecClass),
		C.CFTypeRef(C.kSecAttrService),
		C.CFTypeRef(C.kSecAttrAccount),
	}
	queryValues := []C.CFTypeRef{
		C.CFTypeRef(C.kSecClassGenericPassword),
		C.CFTypeRef(serviceCF),
		C.CFTypeRef(accountCF),
	}

	query := cfDictionary(queryKeys, queryValues)
	defer C.CFRelease(C.CFTypeRef(query))

	// Probe for existing item.
	status := C.SecItemCopyMatching(query, nil)
	if status == C.errSecSuccess {
		// Item exists -- update it.
		updateKeys := []C.CFTypeRef{
			C.CFTypeRef(C.kSecValueData),
		}
		updateValues := []C.CFTypeRef{
			C.CFTypeRef(dataCF),
		}
		attrs := cfDictionary(updateKeys, updateValues)
		defer C.CFRelease(C.CFTypeRef(attrs))

		status = C.SecItemUpdate(query, attrs)
		if status != C.errSecSuccess {
			return fmt.Errorf("SecItemUpdate failed: OSStatus %d", status)
		}
		return nil
	}

	if status != C.errSecItemNotFound {
		return fmt.Errorf("SecItemCopyMatching (probe) failed: OSStatus %d", status)
	}

	// Item does not exist -- create it with access control.
	label := "Caddy Encrypted Storage - Age Identity"
	labelCF := cfString(label)
	defer C.CFRelease(C.CFTypeRef(labelCF))

	accessDesc := fmt.Sprintf("anchor apple or certificate leaf[subject.OU] = \"%s\"", s.teamID)
	access, err := s.createAccess(accessDesc)
	if err != nil {
		return fmt.Errorf("creating keychain access control: %w", err)
	}
	defer C.CFRelease(C.CFTypeRef(access))

	addKeys := []C.CFTypeRef{
		C.CFTypeRef(C.kSecClass),
		C.CFTypeRef(C.kSecAttrService),
		C.CFTypeRef(C.kSecAttrAccount),
		C.CFTypeRef(C.kSecAttrLabel),
		C.CFTypeRef(C.kSecValueData),
		C.CFTypeRef(C.kSecAttrAccess),
	}
	addValues := []C.CFTypeRef{
		C.CFTypeRef(C.kSecClassGenericPassword),
		C.CFTypeRef(serviceCF),
		C.CFTypeRef(accountCF),
		C.CFTypeRef(labelCF),
		C.CFTypeRef(dataCF),
		C.CFTypeRef(access),
	}

	addDict := cfDictionary(addKeys, addValues)
	defer C.CFRelease(C.CFTypeRef(addDict))

	status = C.SecItemAdd(addDict, nil)
	if status != C.errSecSuccess {
		return fmt.Errorf("SecItemAdd failed: OSStatus %d", status)
	}
	return nil
}

// Delete removes the keychain item for the given service and account.
// Returns ErrNotFound if the item does not exist.
func (s *darwinStore) Delete(service, account string) error {
	serviceCF := cfString(service)
	defer C.CFRelease(C.CFTypeRef(serviceCF))

	accountCF := cfString(account)
	defer C.CFRelease(C.CFTypeRef(accountCF))

	keys := []C.CFTypeRef{
		C.CFTypeRef(C.kSecClass),
		C.CFTypeRef(C.kSecAttrService),
		C.CFTypeRef(C.kSecAttrAccount),
	}
	values := []C.CFTypeRef{
		C.CFTypeRef(C.kSecClassGenericPassword),
		C.CFTypeRef(serviceCF),
		C.CFTypeRef(accountCF),
	}

	query := cfDictionary(keys, values)
	defer C.CFRelease(C.CFTypeRef(query))

	status := C.SecItemDelete(query)
	if status == C.errSecItemNotFound {
		return ErrNotFound
	}
	if status != C.errSecSuccess {
		return fmt.Errorf("SecItemDelete failed: OSStatus %d", status)
	}
	return nil
}
