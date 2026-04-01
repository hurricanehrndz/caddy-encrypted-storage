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

// darwinStore implements Store using the macOS Keychain. When keychain
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

// useCustomKeychain reports whether this store targets a custom keychain
// rather than the default search list.
func (s *darwinStore) useCustomKeychain() bool {
	return s.keychain != 0
}

// ensurePassword reads the keychain password from path, or generates a
// new random one and writes it.
func ensurePassword(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err == nil && len(data) > 0 {
		return string(data), nil
	}
	if err != nil && !os.IsNotExist(err) {
		return "", fmt.Errorf("reading password file: %w", err)
	}

	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generating random password: %w", err)
	}
	pass := hex.EncodeToString(buf)

	if err := os.WriteFile(path, []byte(pass), 0o600); err != nil {
		return "", fmt.Errorf("writing password file: %w", err)
	}
	return pass, nil
}

// openOrCreateKeychain opens an existing custom keychain or creates one.
func openOrCreateKeychain(path, password string) (C.SecKeychainRef, error) {
	pathC := C.CString(path)
	defer C.free(unsafe.Pointer(pathC))

	passC := C.CString(password)
	defer C.free(unsafe.Pointer(passC))

	var kc C.SecKeychainRef

	// Try to open an existing keychain first.
	status := C.SecKeychainOpen(pathC, &kc)
	if status == C.errSecSuccess {
		// Verify it's usable by unlocking it.
		status = C.SecKeychainUnlock(kc, C.UInt32(len(password)), unsafe.Pointer(passC), C.Boolean(1))
		if status == C.errSecSuccess {
			return kc, nil
		}
		// Unlock failed — might be corrupted or wrong password.
		// Fall through to create a new one.
		C.CFRelease(C.CFTypeRef(kc))
	}

	// Create a new keychain.
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

	if s.useCustomKeychain() {
		searchListCF := s.searchListCF()
		defer C.CFRelease(C.CFTypeRef(searchListCF))
		keys = append(keys, C.CFTypeRef(C.kSecMatchSearchList))
		values = append(values, C.CFTypeRef(searchListCF))
	}

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

// searchListCF returns a CFArrayRef containing the custom keychain.
// The caller must release the returned ref.
func (s *darwinStore) searchListCF() C.CFArrayRef {
	searchList := []C.CFTypeRef{C.CFTypeRef(s.keychain)}
	return C.CFArrayCreate(
		C.kCFAllocatorDefault,
		(*unsafe.Pointer)(unsafe.Pointer(&searchList[0])),
		C.CFIndex(1),
		&C.kCFTypeArrayCallBacks,
	)
}

// HasTrustedAppACL verifies that the keychain item for the given service and
// account has a non-empty trusted application list on its decrypt ACL. This
// confirms that access is restricted to specific applications rather than
// being open to all. Exported for testing.
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
			str, _ := goStringFromCF(authStr)
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
		defer C.CFRelease(C.CFTypeRef(appList))
		return C.CFArrayGetCount(appList) > 0, nil
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

	if s.useCustomKeychain() {
		searchListCF := s.searchListCF()
		defer C.CFRelease(C.CFTypeRef(searchListCF))
		keys = append(keys, C.CFTypeRef(C.kSecMatchSearchList))
		values = append(values, C.CFTypeRef(searchListCF))
	}

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

	data := goBytes(C.CFDataRef(result))
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

	if s.useCustomKeychain() {
		searchListCF := s.searchListCF()
		defer C.CFRelease(C.CFTypeRef(searchListCF))
		keys = append(keys, C.CFTypeRef(C.kSecMatchSearchList))
		values = append(values, C.CFTypeRef(searchListCF))
	}

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
	data = goBytes(C.CFDataRef(dataPtr))

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

	if s.useCustomKeychain() {
		searchListCF := s.searchListCF()
		defer C.CFRelease(C.CFTypeRef(searchListCF))
		queryKeys = append(queryKeys, C.CFTypeRef(C.kSecMatchSearchList))
		queryValues = append(queryValues, C.CFTypeRef(searchListCF))
	}

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

	if s.useCustomKeychain() {
		searchListCF := s.searchListCF()
		defer C.CFRelease(C.CFTypeRef(searchListCF))
		keys = append(keys, C.CFTypeRef(C.kSecMatchSearchList))
		values = append(values, C.CFTypeRef(searchListCF))
	}

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
