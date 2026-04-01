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
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"
)

// Constants for the custom keychain layout used by NewCustom.
const (
	keychainDir  = ".caddy-keychain"
	keychainFile = "caddy-encrypted-storage.keychain-db"
	passwordFile = ".password"
)

// darwinStore implements Store using the macOS Keychain. When `keychain`
// is non-zero a custom keychain is targeted; otherwise the default
// keychain search list (login + system) is used.
type darwinStore struct {
	keychain     C.SecKeychainRef
	keychainPass string
}

// New creates a Store backed by the default macOS keychain search list
// (login keychain for regular users, system keychain for root).
func New() (Store, error) {
	return &darwinStore{}, nil
}

// NewCustom creates a Store backed by a custom macOS Keychain located
// in storageRoot/.caddy-keychain/. The keychain is created on first
// use with a random password stored alongside it. This is intended for
// testing where the default keychain should not be used.
func NewCustom(storageRoot string) (Store, error) {
	dir := filepath.Join(storageRoot, keychainDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("creating keychain directory: %w", err)
	}

	passPath := filepath.Join(dir, passwordFile)
	kcPath := filepath.Join(dir, keychainFile)

	pass, err := ensurePassword(passPath)
	if err != nil {
		return nil, fmt.Errorf("keychain password: %w", err)
	}

	kc, err := openOrCreateKeychain(kcPath, pass)
	if err != nil {
		return nil, fmt.Errorf("keychain open/create: %w", err)
	}

	return &darwinStore{
		keychain:     kc,
		keychainPass: pass,
	}, nil
}

// Close releases the custom keychain reference, if any. It is a no-op
// for stores using the default keychain search list. Safe to call
// multiple times.
func (s *darwinStore) Close() error {
	if s.keychain != 0 {
		C.CFRelease(C.CFTypeRef(s.keychain))
		s.keychain = 0
	}
	return nil
}

// useCustomKeychain reports whether this store targets a custom keychain
// rather than the default search list.
func (s *darwinStore) useCustomKeychain() bool {
	return s.keychain != 0
}

// ensurePassword reads the keychain password from path, or generates a
// new random one and writes it.
func ensurePassword(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		if len(data) > 0 {
			return string(data), nil
		}
		return "", fmt.Errorf("password file %q exists but is empty; "+
			"this may indicate a corrupted state — delete the file and "+
			"the keychain to reset", path)
	}
	if !os.IsNotExist(err) {
		return "", fmt.Errorf("reading password file: %w", err)
	}

	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generating random password: %w", err)
	}
	pass := hex.EncodeToString(buf)

	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		if os.IsExist(err) {
			// Another process won the race — read its password.
			data, readErr := os.ReadFile(path)
			if readErr != nil {
				return "", fmt.Errorf("reading password file after race: %w", readErr)
			}
			if len(data) == 0 {
				return "", fmt.Errorf("password file %q exists but is empty after race", path)
			}
			return string(data), nil
		}
		return "", fmt.Errorf("creating password file: %w", err)
	}
	if _, err := f.WriteString(pass); err != nil {
		f.Close()
		os.Remove(path)
		return "", fmt.Errorf("writing password file: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(path)
		return "", fmt.Errorf("syncing password file: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(path)
		return "", fmt.Errorf("closing password file: %w", err)
	}
	return pass, nil
}

// openOrCreateKeychain opens an existing custom keychain or creates one.
// If the keychain file exists but cannot be unlocked (e.g. wrong password),
// an error is returned rather than silently replacing the keychain.
func openOrCreateKeychain(path, password string) (C.SecKeychainRef, error) {
	pathC := C.CString(path)
	defer C.free(unsafe.Pointer(pathC))

	passC := C.CString(password)
	defer C.free(unsafe.Pointer(passC))

	var kc C.SecKeychainRef

	// Try to open an existing keychain first.
	// Note: SecKeychainOpen always succeeds — it merely records the path
	// without verifying the file exists.
	status := C.SecKeychainOpen(pathC, &kc)
	if status == C.errSecSuccess {
		// Verify it's usable by unlocking it.
		status = C.SecKeychainUnlock(kc, C.UInt32(len(password)), unsafe.Pointer(passC), C.Boolean(1))
		if status == C.errSecSuccess {
			return kc, nil
		}
		unlockErr := secError("SecKeychainUnlock", status)
		C.CFRelease(C.CFTypeRef(kc))

		// Only create a new keychain if the file does not exist on disk.
		// If it exists but unlock failed (wrong password, corruption),
		// return an error to avoid silently replacing the keychain and
		// losing the stored identity.
		if _, statErr := os.Stat(path); statErr == nil {
			return 0, fmt.Errorf("keychain exists at %s but unlock failed: %w; "+
				"if the keychain is corrupted, delete it and its password file to reset", path, unlockErr)
		} else if !os.IsNotExist(statErr) {
			return 0, fmt.Errorf("keychain unlock failed (%w) and cannot determine "+
				"if keychain file exists: %v", unlockErr, statErr)
		}

		status = C.SecKeychainCreate(pathC, C.UInt32(len(password)), unsafe.Pointer(passC),
			C.Boolean(0), 0, &kc)
		if status != C.errSecSuccess {
			return 0, fmt.Errorf("keychain file missing (unlock had failed: %v) "+
				"and creating new keychain also failed: %s", unlockErr, secErrorMessage(status))
		}
		return kc, nil
	}

	// No existing keychain — create a new one.
	status = C.SecKeychainCreate(pathC, C.UInt32(len(password)), unsafe.Pointer(passC),
		C.Boolean(0), // promptUser = false
		0,            // initialAccess = NULL (default)
		&kc)
	if status != C.errSecSuccess {
		return 0, secError("SecKeychainCreate", status)
	}

	return kc, nil
}

// ---------------------------------------------------------------------------
// Error helpers
// ---------------------------------------------------------------------------

// secErrorMessage maps common Security Framework OSStatus codes to
// human-readable descriptions.
func secErrorMessage(status C.OSStatus) string {
	switch status {
	case C.errSecSuccess:
		return "no error"
	case C.errSecItemNotFound:
		return "item not found"
	case C.errSecDuplicateItem:
		return "duplicate item"
	case C.errSecAuthFailed:
		return "authorization/authentication failed"
	case C.errSecInteractionNotAllowed:
		return "user interaction not allowed"
	case C.errSecDecode:
		return "unable to decode data"
	case C.errSecParam:
		return "invalid parameter"
	case -25240: // errSecNoAccessForItem
		return "the specified item has no access control"
	default:
		return fmt.Sprintf("OSStatus %d", status)
	}
}

// secError returns an error wrapping the given Security Framework status code.
func secError(operation string, status C.OSStatus) error {
	return fmt.Errorf("%s failed: %s", operation, secErrorMessage(status))
}

// ---------------------------------------------------------------------------
// CoreFoundation helpers
// ---------------------------------------------------------------------------

// cfString creates a CFStringRef from a Go string. The caller must release
// the returned reference with C.CFRelease. Returns a non-zero ref or an error.
func cfString(s string) (C.CFStringRef, error) {
	cs := C.CString(s)
	defer C.free(unsafe.Pointer(cs))
	ref := C.CFStringCreateWithCString(C.kCFAllocatorDefault, cs, C.kCFStringEncodingUTF8)
	if ref == 0 {
		return 0, fmt.Errorf("CFStringCreateWithCString returned NULL for %q", s)
	}
	return ref, nil
}

// cfData creates a CFDataRef from a Go byte slice. The caller must release
// the returned reference with C.CFRelease. Returns a non-zero ref or an error.
func cfData(b []byte) (C.CFDataRef, error) {
	var ref C.CFDataRef
	if len(b) == 0 {
		ref = C.CFDataCreate(C.kCFAllocatorDefault, nil, 0)
	} else {
		ref = C.CFDataCreate(C.kCFAllocatorDefault, (*C.UInt8)(unsafe.Pointer(&b[0])), C.CFIndex(len(b)))
	}
	if ref == 0 {
		return 0, fmt.Errorf("CFDataCreate returned NULL")
	}
	return ref, nil
}

// cfDictionary builds an immutable CFDictionary from parallel slices of keys
// and values. The caller must release the returned reference with C.CFRelease.
// Returns a non-zero ref or an error.
func cfDictionary(keys []C.CFTypeRef, values []C.CFTypeRef) (C.CFDictionaryRef, error) {
	ref := C.CFDictionaryCreate(
		C.kCFAllocatorDefault,
		(*unsafe.Pointer)(unsafe.Pointer(&keys[0])),
		(*unsafe.Pointer)(unsafe.Pointer(&values[0])),
		C.CFIndex(len(keys)),
		&C.kCFTypeDictionaryKeyCallBacks,
		&C.kCFTypeDictionaryValueCallBacks,
	)
	if ref == 0 {
		return 0, fmt.Errorf("CFDictionaryCreate returned NULL")
	}
	return ref, nil
}

// goBytes converts a CFDataRef to a Go byte slice. Returns an error if ref is 0.
func goBytes(ref C.CFDataRef) ([]byte, error) {
	if ref == 0 {
		return nil, fmt.Errorf("cannot convert NULL CFDataRef to Go bytes")
	}
	length := C.CFDataGetLength(ref)
	if length == 0 {
		return []byte{}, nil
	}
	ptr := C.CFDataGetBytePtr(ref)
	return C.GoBytes(unsafe.Pointer(ptr), C.int(length)), nil
}

// goStringFromCF converts a CFStringRef to a Go string.
// Returns an error if ref is 0 or the string cannot be decoded.
func goStringFromCF(ref C.CFStringRef) (string, error) {
	if ref == 0 {
		return "", fmt.Errorf("cannot convert NULL CFStringRef to Go string")
	}
	cstr := C.CFStringGetCStringPtr(ref, C.kCFStringEncodingUTF8)
	if cstr != nil {
		return C.GoString(cstr), nil
	}
	length := C.CFStringGetLength(ref)
	maxSize := C.CFStringGetMaximumSizeForEncoding(length, C.kCFStringEncodingUTF8) + 1
	buf := C.malloc(C.size_t(maxSize))
	defer C.free(buf)
	if C.CFStringGetCString(ref, (*C.char)(buf), maxSize, C.kCFStringEncodingUTF8) == C.Boolean(0) {
		return "", fmt.Errorf("CFStringGetCString failed to decode string")
	}
	return C.GoString((*C.char)(buf)), nil
}

// ---------------------------------------------------------------------------
// SecAccess / ACL helpers
// ---------------------------------------------------------------------------

// createAccess builds a SecAccessRef that restricts keychain item access to
// the current application (self).
func (s *darwinStore) createAccess(description string) (C.SecAccessRef, error) {
	var selfApp C.SecTrustedApplicationRef
	status := C.SecTrustedApplicationCreateFromPath(nil, &selfApp)
	if status != C.errSecSuccess {
		return 0, secError("SecTrustedApplicationCreateFromPath", status)
	}
	defer C.CFRelease(C.CFTypeRef(selfApp))

	apps := []C.CFTypeRef{C.CFTypeRef(selfApp)}
	trustedApps := C.CFArrayCreate(
		C.kCFAllocatorDefault,
		(*unsafe.Pointer)(unsafe.Pointer(&apps[0])),
		C.CFIndex(len(apps)),
		&C.kCFTypeArrayCallBacks,
	)
	if trustedApps == 0 {
		return 0, fmt.Errorf("CFArrayCreate returned NULL for trusted apps")
	}
	defer C.CFRelease(C.CFTypeRef(trustedApps))

	descCF, err := cfString(description)
	if err != nil {
		return 0, fmt.Errorf("creating access description: %w", err)
	}
	defer C.CFRelease(C.CFTypeRef(descCF))

	var access C.SecAccessRef
	status = C.SecAccessCreate(descCF, trustedApps, &access)
	if status != C.errSecSuccess {
		return 0, secError("SecAccessCreate", status)
	}
	return access, nil
}

// getItemRef retrieves a SecKeychainItemRef for the given service and account.
// The caller must release the returned ref.
func (s *darwinStore) getItemRef(service, account string) (C.SecKeychainItemRef, error) {
	serviceCF, err := cfString(service)
	if err != nil {
		return 0, fmt.Errorf("creating service string: %w", err)
	}
	defer C.CFRelease(C.CFTypeRef(serviceCF))

	accountCF, err := cfString(account)
	if err != nil {
		return 0, fmt.Errorf("creating account string: %w", err)
	}
	defer C.CFRelease(C.CFTypeRef(accountCF))

	keys := []C.CFTypeRef{
		C.CFTypeRef(C.kSecClass),
		C.CFTypeRef(C.kSecAttrService),
		C.CFTypeRef(C.kSecAttrAccount),
		C.CFTypeRef(C.kSecReturnRef),
		C.CFTypeRef(C.kSecMatchLimit),
	}
	values := []C.CFTypeRef{
		C.CFTypeRef(C.kSecClassGenericPassword),
		C.CFTypeRef(serviceCF),
		C.CFTypeRef(accountCF),
		C.CFTypeRef(C.kCFBooleanTrue),
		C.CFTypeRef(C.kSecMatchLimitOne),
	}

	cleanup, err := s.appendSearchList(&keys, &values)
	if err != nil {
		return 0, err
	}
	defer cleanup()

	query, err := cfDictionary(keys, values)
	if err != nil {
		return 0, fmt.Errorf("creating query dictionary: %w", err)
	}
	defer C.CFRelease(C.CFTypeRef(query))

	var result C.CFTypeRef
	status := C.SecItemCopyMatching(query, &result)
	if status == C.errSecItemNotFound {
		return 0, ErrNotFound
	}
	if status != C.errSecSuccess {
		return 0, secError("SecItemCopyMatching", status)
	}
	return C.SecKeychainItemRef(result), nil
}

// appendSearchList appends kSecMatchSearchList targeting the custom keychain
// to the given query key/value slices. If the store uses the default keychain,
// this is a no-op. The returned cleanup function must be called to release the
// CFArrayRef (it is safe to call even when no array was created).
func (s *darwinStore) appendSearchList(keys, values *[]C.CFTypeRef) (cleanup func(), err error) {
	noop := func() {}
	if !s.useCustomKeychain() {
		return noop, nil
	}
	items := []C.CFTypeRef{C.CFTypeRef(s.keychain)}
	ref := C.CFArrayCreate(
		C.kCFAllocatorDefault,
		(*unsafe.Pointer)(unsafe.Pointer(&items[0])),
		C.CFIndex(1),
		&C.kCFTypeArrayCallBacks,
	)
	if ref == 0 {
		return noop, fmt.Errorf("CFArrayCreate returned NULL for search list")
	}
	*keys = append(*keys, C.CFTypeRef(C.kSecMatchSearchList))
	*values = append(*values, C.CFTypeRef(ref))
	return func() { C.CFRelease(C.CFTypeRef(ref)) }, nil
}

// HasTrustedAppACL verifies that the keychain item for the given service and
// account has a non-empty trusted application list on its decrypt ACL. This
// confirms that access is restricted to specific applications rather than
// being open to all. Used by tests in this package via type assertion.
func (s *darwinStore) HasTrustedAppACL(service, account string) (bool, error) {
	itemRef, err := s.getItemRef(service, account)
	if err != nil {
		return false, err
	}
	defer C.CFRelease(C.CFTypeRef(itemRef))

	var accessRef C.SecAccessRef
	status := C.SecKeychainItemCopyAccess(itemRef, &accessRef)
	if status != C.errSecSuccess {
		return false, secError("SecKeychainItemCopyAccess", status)
	}
	defer C.CFRelease(C.CFTypeRef(accessRef))

	var aclList C.CFArrayRef
	status = C.SecAccessCopyACLList(accessRef, &aclList)
	if status != C.errSecSuccess {
		return false, secError("SecAccessCopyACLList", status)
	}
	defer C.CFRelease(C.CFTypeRef(aclList))

	count := C.CFArrayGetCount(aclList)
	for i := C.CFIndex(0); i < count; i++ {
		acl := C.SecACLRef(C.CFArrayGetValueAtIndex(aclList, i))

		authsRef := C.SecACLCopyAuthorizations(acl)
		if authsRef == 0 {
			continue
		}

		// Check if this ACL covers ACLAuthorizationDecrypt.
		authCount := C.CFArrayGetCount(authsRef)
		found := false
		for j := C.CFIndex(0); j < authCount; j++ {
			authStr := C.CFStringRef(C.CFArrayGetValueAtIndex(authsRef, j))
			str, err := goStringFromCF(authStr)
			if err != nil {
				C.CFRelease(C.CFTypeRef(authsRef))
				return false, fmt.Errorf("decoding ACL authorization string: %w", err)
			}
			if str == "ACLAuthorizationDecrypt" {
				found = true
				break
			}
		}
		C.CFRelease(C.CFTypeRef(authsRef))

		if !found {
			continue
		}

		// Read the trusted app list for this ACL.
		var appList C.CFArrayRef
		var desc C.CFStringRef
		var prompt C.SecKeychainPromptSelector
		status = C.SecACLCopyContents(acl, &appList, &desc, &prompt)
		if status != C.errSecSuccess {
			return false, secError("SecACLCopyContents", status)
		}
		if desc != 0 {
			C.CFRelease(C.CFTypeRef(desc))
		}
		if appList == 0 {
			return false, nil // nil app list = any app can access
		}
		hasApps := C.CFArrayGetCount(appList) > 0
		C.CFRelease(C.CFTypeRef(appList))
		return hasApps, nil
	}

	return false, fmt.Errorf("ACLAuthorizationDecrypt not found")
}

// ---------------------------------------------------------------------------
// Store interface implementation
// ---------------------------------------------------------------------------

// Get retrieves the credential data for the given service and account.
// Returns ErrNotFound if the item does not exist.
func (s *darwinStore) Get(service, account string) ([]byte, error) {
	serviceCF, err := cfString(service)
	if err != nil {
		return nil, fmt.Errorf("creating service string: %w", err)
	}
	defer C.CFRelease(C.CFTypeRef(serviceCF))

	accountCF, err := cfString(account)
	if err != nil {
		return nil, fmt.Errorf("creating account string: %w", err)
	}
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

	cleanup, err := s.appendSearchList(&keys, &values)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	query, err := cfDictionary(keys, values)
	if err != nil {
		return nil, fmt.Errorf("creating query dictionary: %w", err)
	}
	defer C.CFRelease(C.CFTypeRef(query))

	var result C.CFTypeRef
	status := C.SecItemCopyMatching(query, &result)
	if status == C.errSecItemNotFound {
		return nil, ErrNotFound
	}
	if status != C.errSecSuccess {
		return nil, secError("SecItemCopyMatching", status)
	}
	defer C.CFRelease(result)

	data, err := goBytes(C.CFDataRef(result))
	if err != nil {
		return nil, fmt.Errorf("reading credential data: %w", err)
	}
	return data, nil
}

// GetFirst retrieves the first credential matching the given service name.
// Returns ErrNotFound if no credentials exist for the service.
func (s *darwinStore) GetFirst(service string) (data []byte, account string, err error) {
	serviceCF, err := cfString(service)
	if err != nil {
		return nil, "", fmt.Errorf("creating service string: %w", err)
	}
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

	cleanup, err := s.appendSearchList(&keys, &values)
	if err != nil {
		return nil, "", err
	}
	defer cleanup()

	query, err := cfDictionary(keys, values)
	if err != nil {
		return nil, "", fmt.Errorf("creating query dictionary: %w", err)
	}
	defer C.CFRelease(C.CFTypeRef(query))

	var result C.CFTypeRef
	status := C.SecItemCopyMatching(query, &result)
	if status == C.errSecItemNotFound {
		return nil, "", ErrNotFound
	}
	if status != C.errSecSuccess {
		return nil, "", secError("SecItemCopyMatching", status)
	}
	defer C.CFRelease(result)

	dict := C.CFDictionaryRef(result)

	dataPtr := C.CFDictionaryGetValue(dict, unsafe.Pointer(C.kSecValueData))
	if dataPtr == nil {
		return nil, "", fmt.Errorf("keychain item missing value data")
	}
	data, err = goBytes(C.CFDataRef(dataPtr))
	if err != nil {
		return nil, "", fmt.Errorf("reading credential data: %w", err)
	}

	accountPtr := C.CFDictionaryGetValue(dict, unsafe.Pointer(C.kSecAttrAccount))
	if accountPtr == nil {
		return nil, "", fmt.Errorf("keychain item missing account attribute")
	}
	account, err = goStringFromCF(C.CFStringRef(accountPtr))
	if err != nil {
		return nil, "", fmt.Errorf("decoding account name: %w", err)
	}

	return data, account, nil
}

// Set creates or updates a keychain item. New items are created with an
// ACL restricting access to self (the current application).
func (s *darwinStore) Set(service, account string, data []byte) error {
	serviceCF, err := cfString(service)
	if err != nil {
		return fmt.Errorf("creating service string: %w", err)
	}
	defer C.CFRelease(C.CFTypeRef(serviceCF))

	accountCF, err := cfString(account)
	if err != nil {
		return fmt.Errorf("creating account string: %w", err)
	}
	defer C.CFRelease(C.CFTypeRef(accountCF))

	dataCF, err := cfData(data)
	if err != nil {
		return fmt.Errorf("creating data: %w", err)
	}
	defer C.CFRelease(C.CFTypeRef(dataCF))

	// Probe for existing item.
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

	cleanup, err := s.appendSearchList(&queryKeys, &queryValues)
	if err != nil {
		return err
	}
	defer cleanup()

	query, err := cfDictionary(queryKeys, queryValues)
	if err != nil {
		return fmt.Errorf("creating query dictionary: %w", err)
	}
	defer C.CFRelease(C.CFTypeRef(query))

	status := C.SecItemCopyMatching(query, nil)
	if status == C.errSecSuccess {
		// Item exists — update it.
		updateKeys := []C.CFTypeRef{C.CFTypeRef(C.kSecValueData)}
		updateValues := []C.CFTypeRef{C.CFTypeRef(dataCF)}
		attrs, err := cfDictionary(updateKeys, updateValues)
		if err != nil {
			return fmt.Errorf("creating update dictionary: %w", err)
		}
		defer C.CFRelease(C.CFTypeRef(attrs))

		status = C.SecItemUpdate(query, attrs)
		if status != C.errSecSuccess {
			return secError("SecItemUpdate", status)
		}
		return nil
	}

	if status != C.errSecItemNotFound {
		return secError("SecItemCopyMatching (probe)", status)
	}

	// Item does not exist — create it with ACL.
	label := "Caddy Encrypted Storage - Age Identity"
	labelCF, err := cfString(label)
	if err != nil {
		return fmt.Errorf("creating label string: %w", err)
	}
	defer C.CFRelease(C.CFTypeRef(labelCF))

	access, err := s.createAccess("Caddy Encrypted Storage")
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

	if s.useCustomKeychain() {
		addKeys = append(addKeys, C.CFTypeRef(C.kSecUseKeychain))
		addValues = append(addValues, C.CFTypeRef(s.keychain))
	}

	addDict, err := cfDictionary(addKeys, addValues)
	if err != nil {
		return fmt.Errorf("creating add dictionary: %w", err)
	}
	defer C.CFRelease(C.CFTypeRef(addDict))

	status = C.SecItemAdd(addDict, nil)
	if status != C.errSecSuccess {
		return secError("SecItemAdd", status)
	}

	return nil
}

// Delete removes the keychain item for the given service and account.
// Returns ErrNotFound if the item does not exist.
func (s *darwinStore) Delete(service, account string) error {
	serviceCF, err := cfString(service)
	if err != nil {
		return fmt.Errorf("creating service string: %w", err)
	}
	defer C.CFRelease(C.CFTypeRef(serviceCF))

	accountCF, err := cfString(account)
	if err != nil {
		return fmt.Errorf("creating account string: %w", err)
	}
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

	cleanup, err := s.appendSearchList(&keys, &values)
	if err != nil {
		return err
	}
	defer cleanup()

	query, err := cfDictionary(keys, values)
	if err != nil {
		return fmt.Errorf("creating query dictionary: %w", err)
	}
	defer C.CFRelease(C.CFTypeRef(query))

	status := C.SecItemDelete(query)
	if status == C.errSecItemNotFound {
		return ErrNotFound
	}
	if status != C.errSecSuccess {
		return secError("SecItemDelete", status)
	}
	return nil
}
