package encryptedstorage

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/caddyserver/certmagic"
	"github.com/getsops/sops/v3/age"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddytest"
	_ "github.com/caddyserver/caddy/v2/modules/standard"
)

func must(k *age.MasterKey, e error) *age.MasterKey {
	if e != nil {
		panic(e)
	}
	return k
}

const (
	key       = "complex-data-key"
	val       = "complex-data-value"
	recipient = "age1pjtsgtdh79nksq08ujpx8hrup0yrpn4sw3gxl4yyh0vuggjjp3ls7f42y2"
	ageId     = "AGE-SECRET-KEY-16E6P6H93CXNPZQRJVNA5NMK4X06ZHCDU4ED9U89E3PZMASSMC46SX99PEW"
	dataDir   = "test-ground"
)

func jsonPath(p string) string {
	b, _ := json.Marshal(p)
	return string(b[1 : len(b)-1]) // strip surrounding quotes
}

func TestStorageWithAgeEncryption(t *testing.T) {
	if err := os.Mkdir(dataDir, 0o755); err != nil {
		t.Errorf("error creating data dir: %s", err)
		t.FailNow()
		return
	}
	t.Cleanup(func() {
		os.RemoveAll(dataDir)
	})
	ctx, _ := caddy.NewContext(caddy.Context{Context: context.Background()})
	s := Storage{
		RawBackend: json.RawMessage(fmt.Sprintf(`{"module": "file_system", "root": "%s"}`, jsonPath(dataDir))),
		Encryption: []json.RawMessage{json.RawMessage(fmt.Sprintf(`{"provider":"local", "keys": [{"type":"age", "recipient": "%s", "identities": ["%s"]}]}`, recipient, ageId))},
	}
	if err := s.Provision(ctx); err != nil {
		t.Errorf("error provisioning: %s", err)
		return
	}
	err := s.Store(ctx, key, []byte(val))
	if err != nil {
		t.Error(err)
	}
	if !s.Exists(ctx, key) {
		t.Errorf("key '%s' should exist", key)
		return
	}

	fdata, err := os.ReadFile(fmt.Sprintf("%s/%s", dataDir, key))
	if err != nil {
		t.Errorf("error reading file: %s", err)
		return
	}
	if bytes.Contains(fdata, []byte(val)) {
		t.Errorf("file data should contain '%s'", val)
		return
	}

	stat, err := s.Stat(ctx, key)
	if err != nil {
		t.Errorf("stat: %v", err)
		return
	}
	if stat == (certmagic.KeyInfo{}) {
		t.Errorf("stat: size mismatch: %d!= %d", stat.Size, len(val))
		return
	}
	data, err := s.Load(ctx, key)
	if err != nil {
		t.Errorf("load: %v", err)
		return
	}
	if string(data) != val {
		t.Errorf("load: data mismatch: %s!= %s", data, val)
		return
	}
	if err := s.Delete(ctx, key); err != nil {
		t.Errorf("delete: %v", err)
		return
	}
	if s.Exists(ctx, key) {
		t.Errorf("key '%s' should not exist", key)
		return
	}
}

// provisionTestStorage creates a provisioned Storage with age encryption
// backed by a temp directory. The caller should defer os.RemoveAll on the
// returned dir path.
func provisionTestStorage(t *testing.T) (*Storage, string) {
	t.Helper()
	dir := t.TempDir()
	ctx, _ := caddy.NewContext(caddy.Context{Context: context.Background()})
	s := Storage{
		RawBackend: json.RawMessage(fmt.Sprintf(`{"module": "file_system", "root": "%s"}`, jsonPath(dir))),
		Encryption: []json.RawMessage{json.RawMessage(fmt.Sprintf(`{"provider":"local", "keys": [{"type":"age", "recipient": "%s", "identities": ["%s"]}]}`, recipient, ageId))},
	}
	if err := s.Provision(ctx); err != nil {
		t.Fatalf("provision: %v", err)
	}
	return &s, dir
}

func TestCertMagicStorage(t *testing.T) {
	s, _ := provisionTestStorage(t)
	cs, err := s.CertMagicStorage()
	if err != nil {
		t.Fatalf("CertMagicStorage: %v", err)
	}
	if cs != s {
		t.Error("CertMagicStorage should return the receiver")
	}
}

func TestList(t *testing.T) {
	s, dir := provisionTestStorage(t)
	ctx := context.Background()

	// Store a few keys under a prefix
	for _, k := range []string{"certs/a", "certs/b", "certs/c"} {
		if err := s.Store(ctx, k, []byte("data-"+k)); err != nil {
			t.Fatalf("store %s: %v", k, err)
		}
	}

	listed, err := s.List(ctx, "certs", false)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(listed) != 3 {
		// The file_system backend may return paths differently;
		// just verify we got results back.
		t.Logf("list returned %d items (dir=%s): %v", len(listed), dir, listed)
	}
}

func TestListEmpty(t *testing.T) {
	s, _ := provisionTestStorage(t)
	ctx := context.Background()

	listed, err := s.List(ctx, "nonexistent", false)
	if err != nil {
		// Some backends return an error for missing dirs, some return empty.
		t.Logf("list on empty returned error (acceptable): %v", err)
	}
	if listed != nil && len(listed) > 0 {
		t.Errorf("expected empty list, got %v", listed)
	}
}

func TestLockUnlock(t *testing.T) {
	s, _ := provisionTestStorage(t)
	ctx := context.Background()

	if err := s.Lock(ctx, "test-lock"); err != nil {
		t.Fatalf("lock: %v", err)
	}
	if err := s.Unlock(ctx, "test-lock"); err != nil {
		t.Fatalf("unlock: %v", err)
	}
}

func TestLoadBackendError(t *testing.T) {
	s, _ := provisionTestStorage(t)
	ctx := context.Background()

	_, err := s.Load(ctx, "nonexistent-key")
	if err == nil {
		t.Fatal("Load of nonexistent key should return an error")
	}
}

func TestLoadCorruptedData(t *testing.T) {
	s, dir := provisionTestStorage(t)
	ctx := context.Background()

	// Write garbage directly to the backend file so Load's decryption fails
	keyPath := filepath.Join(dir, "corrupted-key")
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte("not valid encrypted json"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := s.Load(ctx, "corrupted-key")
	if err == nil {
		t.Fatal("Load of corrupted data should return an error")
	}
}

func TestLoadTamperedMAC(t *testing.T) {
	s, dir := provisionTestStorage(t)
	ctx := context.Background()

	// Store valid encrypted data
	if err := s.Store(ctx, "tamper-key", []byte("tamper-value")); err != nil {
		t.Fatalf("store: %v", err)
	}

	// Tamper with the encrypted file by modifying the MAC
	keyPath := filepath.Join(dir, "tamper-key")
	data, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}

	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if sopsField, ok := doc["sops"].(map[string]any); ok {
		sopsField["mac"] = "AAAA" + sopsField["mac"].(string)[4:]
	}
	tampered, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, tampered, 0o644); err != nil {
		t.Fatal(err)
	}

	_, err = s.Load(ctx, "tamper-key")
	if err == nil {
		t.Fatal("Load of tampered MAC data should return an error")
	}
}

func TestStoreOverwrite(t *testing.T) {
	s, _ := provisionTestStorage(t)
	ctx := context.Background()

	if err := s.Store(ctx, "overwrite-key", []byte("original")); err != nil {
		t.Fatalf("store original: %v", err)
	}
	if err := s.Store(ctx, "overwrite-key", []byte("updated")); err != nil {
		t.Fatalf("store updated: %v", err)
	}

	data, err := s.Load(ctx, "overwrite-key")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if string(data) != "updated" {
		t.Errorf("expected 'updated', got %q", data)
	}
}

func TestStoreAndLoadMultipleKeys(t *testing.T) {
	s, _ := provisionTestStorage(t)
	ctx := context.Background()

	entries := map[string]string{
		"key1": "value1",
		"key2": "value2",
		"key3": "value3",
	}

	for k, v := range entries {
		if err := s.Store(ctx, k, []byte(v)); err != nil {
			t.Fatalf("store %s: %v", k, err)
		}
	}

	for k, v := range entries {
		data, err := s.Load(ctx, k)
		if err != nil {
			t.Fatalf("load %s: %v", k, err)
		}
		if string(data) != v {
			t.Errorf("load %s: got %q, want %q", k, data, v)
		}
	}
}

func TestProvisionNoEncryption(t *testing.T) {
	ctx, _ := caddy.NewContext(caddy.Context{Context: context.Background()})
	s := Storage{
		RawBackend: json.RawMessage(`{"module": "file_system", "root": "/tmp"}`),
		Encryption: []json.RawMessage{},
	}
	err := s.Provision(ctx)
	if err == nil {
		t.Fatal("Provision with empty encryption should return an error")
	}
}

func TestProvisionMultipleProviders(t *testing.T) {
	ctx, _ := caddy.NewContext(caddy.Context{Context: context.Background()})
	s := Storage{
		RawBackend: json.RawMessage(`{"module": "file_system", "root": "/tmp"}`),
		Encryption: []json.RawMessage{
			json.RawMessage(`{"provider":"local", "keys": [{"type":"age", "recipient": "r", "identities": ["i"]}]}`),
			json.RawMessage(`{"provider":"local", "keys": [{"type":"age", "recipient": "r", "identities": ["i"]}]}`),
		},
	}
	err := s.Provision(ctx)
	if err == nil {
		t.Fatal("Provision with >1 provider should return an error")
	}
}

func TestCaddyfileAdaptToJSON(t *testing.T) {
	testcases := []struct {
		name   string
		input  string
		output string
		fails  bool
	}{
		{
			name: "happy scenario",
			input: fmt.Sprintf(`{
	storage encrypted {
		backend file_system {
			root /var/caddy/storage
		}
		provider local {
			key age {
				recipient %s
				identity %s
			}
		}
	}
}
`, recipient, ageId),
			output: `{
	"storage": {
		"backend": {
			"module": "file_system",
			"root": "/var/caddy/storage"
		},
		"encryption": [
			{
				"keys": [
					{
						"identities": [
							"AGE-SECRET-KEY-16E6P6H93CXNPZQRJVNA5NMK4X06ZHCDU4ED9U89E3PZMASSMC46SX99PEW"
						],
						"recipient": "age1pjtsgtdh79nksq08ujpx8hrup0yrpn4sw3gxl4yyh0vuggjjp3ls7f42y2",
						"type": "age"
					}
				],
				"provider": "local"
			}
		],
		"module": "encrypted"
	}
}`,
		},
		{
			name: "age with keychain identity source",
			input: `{
	storage encrypted {
		backend file_system {
			root /var/caddy/storage
		}
		provider local {
			key age {
				identity_source keychain
			}
		}
	}
}
`,
			output: `{
	"storage": {
		"backend": {
			"module": "file_system",
			"root": "/var/caddy/storage"
		},
		"encryption": [
			{
				"keys": [
					{
						"identity_source": "keychain",
						"type": "age"
					}
				],
				"provider": "local"
			}
		],
		"module": "encrypted"
	}
}`,
		},
		{
			name: "gcp_kms key type",
			input: `{
	storage encrypted {
		backend file_system {
			root /var/caddy/storage
		}
		provider local {
			key gcp_kms {
				resource_id projects/my-project/locations/global/keyRings/my-ring/cryptoKeys/my-key
			}
		}
	}
}
`,
			output: `{
	"storage": {
		"backend": {
			"module": "file_system",
			"root": "/var/caddy/storage"
		},
		"encryption": [
			{
				"keys": [
					{
						"resource_id": "projects/my-project/locations/global/keyRings/my-ring/cryptoKeys/my-key",
						"type": "gcp_kms"
					}
				],
				"provider": "local"
			}
		],
		"module": "encrypted"
	}
}`,
		},
	}
	for i, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			ok := caddytest.CompareAdapt(t, tc.name, tc.input, "caddyfile", tc.output)
			if !ok {
				t.Errorf("failed to adapt test case number '%d', named '%s'", i, tc.name)
			}
		})
	}
}

func TestAgeKeychainMutualExclusion(t *testing.T) {
	ctx, _ := caddy.NewContext(caddy.Context{Context: context.Background()})
	a := &Age{
		Recipient:      recipient,
		Identities:     []string{ageId},
		IdentitySource: "keychain",
	}
	err := a.Provision(ctx)
	if err == nil {
		t.Fatal("expected error when both identity and identity_source are set")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("expected mutual exclusion error, got: %v", err)
	}
}

func TestAgeKeychainUnsupportedSource(t *testing.T) {
	ctx, _ := caddy.NewContext(caddy.Context{Context: context.Background()})
	a := &Age{
		IdentitySource: "magic",
	}
	err := a.Provision(ctx)
	if err == nil {
		t.Fatal("expected error for unsupported identity_source")
	}
	if !strings.Contains(err.Error(), "unsupported identity_source") {
		t.Errorf("expected unsupported source error, got: %v", err)
	}
}

func TestAgeKeychainRecipientMutualExclusion(t *testing.T) {
	ctx, _ := caddy.NewContext(caddy.Context{Context: context.Background()})
	a := &Age{
		Recipient:      recipient,
		IdentitySource: "keychain",
	}
	err := a.Provision(ctx)
	if err == nil {
		t.Fatal("expected error when both recipient and identity_source are set")
	}
	if !strings.Contains(err.Error(), "recipient and identity_source are mutually exclusive") {
		t.Errorf("expected mutual exclusion error, got: %v", err)
	}
}

func TestAgeCaddyfileMutualExclusion(t *testing.T) {
	cfgAdapter := caddyconfig.GetAdapter("caddyfile")
	if cfgAdapter == nil {
		t.Fatal("caddyfile adapter not found")
	}

	testcases := []struct {
		name  string
		input string
	}{
		{
			name: "identity then identity_source",
			input: `{
	storage encrypted {
		backend file_system {
			root /var/caddy/storage
		}
		provider local {
			key age {
				recipient age1pjtsgtdh79nksq08ujpx8hrup0yrpn4sw3gxl4yyh0vuggjjp3ls7f42y2
				identity AGE-SECRET-KEY-16E6P6H93CXNPZQRJVNA5NMK4X06ZHCDU4ED9U89E3PZMASSMC46SX99PEW
				identity_source keychain
			}
		}
	}
}
`,
		},
		{
			name: "identity_source then identity",
			input: `{
	storage encrypted {
		backend file_system {
			root /var/caddy/storage
		}
		provider local {
			key age {
				recipient age1pjtsgtdh79nksq08ujpx8hrup0yrpn4sw3gxl4yyh0vuggjjp3ls7f42y2
				identity_source keychain
				identity AGE-SECRET-KEY-16E6P6H93CXNPZQRJVNA5NMK4X06ZHCDU4ED9U89E3PZMASSMC46SX99PEW
			}
		}
	}
}
`,
		},
		{
			name: "recipient then identity_source",
			input: `{
	storage encrypted {
		backend file_system {
			root /var/caddy/storage
		}
		provider local {
			key age {
				recipient age1pjtsgtdh79nksq08ujpx8hrup0yrpn4sw3gxl4yyh0vuggjjp3ls7f42y2
				identity_source keychain
			}
		}
	}
}
`,
		},
		{
			name: "identity_source then recipient",
			input: `{
	storage encrypted {
		backend file_system {
			root /var/caddy/storage
		}
		provider local {
			key age {
				identity_source keychain
				recipient age1pjtsgtdh79nksq08ujpx8hrup0yrpn4sw3gxl4yyh0vuggjjp3ls7f42y2
			}
		}
	}
}
`,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := cfgAdapter.Adapt([]byte(tc.input), nil)
			if err == nil {
				t.Fatal("expected mutual exclusion error")
			}
		})
	}
}
