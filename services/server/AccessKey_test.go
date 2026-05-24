package server

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/semaphoreui/semaphore/db"
	"github.com/semaphoreui/semaphore/util"
)

func TestSetSecret(t *testing.T) {
	accessKey := db.AccessKey{
		Type: db.AccessKeySSH,
		Name: "test",
		SshKey: db.SshKey{
			PrivateKey: "qerphqeruqoweurqwerqqeuiqwpavqr",
		},
	}

	encryptionService := NewAccessKeyEncryptionService(nil, nil, nil, nil)

	util.Config = &util.ConfigType{}
	err := encryptionService.SerializeSecret(&accessKey)

	if err != nil {
		t.Fatal(err)
	}

	secret, err := base64.StdEncoding.DecodeString(*accessKey.Secret)

	if err != nil {
		t.Error(err)
	}

	if string(secret) != "{\"login\":\"\",\"passphrase\":\"\",\"private_key\":\"qerphqeruqoweurqwerqqeuiqwpavqr\"}" {
		t.Error("invalid secret")
	}
}

func TestGetSecret(t *testing.T) {
	secret := base64.StdEncoding.EncodeToString([]byte(`{
	"passphrase": "123456",
	"private_key": "qerphqeruqoweurqwerqqeuiqwpavqr"
}`))
	util.Config = &util.ConfigType{}

	encryptionService := NewAccessKeyEncryptionService(nil, nil, nil, nil)

	accessKey := db.AccessKey{
		Secret: &secret,
		Type:   db.AccessKeySSH,
	}

	err := encryptionService.DeserializeSecret(&accessKey)

	if err != nil {
		t.Error(err)
	}

	if accessKey.SshKey.Passphrase != "123456" {
		t.Errorf("")
	}

	if accessKey.SshKey.PrivateKey != "qerphqeruqoweurqwerqqeuiqwpavqr" {
		t.Errorf("")
	}
}

func TestSetGetSecretWithEncryption(t *testing.T) {

	encryptionService := NewAccessKeyEncryptionService(nil, nil, nil, nil)

	accessKey := db.AccessKey{
		Name: "test",
		Type: db.AccessKeySSH,
		SshKey: db.SshKey{
			PrivateKey: "qerphqeruqoweurqwerqqeuiqwpavqr",
		},
	}

	util.Config = &util.ConfigType{
		AccessKeyEncryption: "hHYgPrhQTZYm7UFTvcdNfKJMB3wtAXtJENUButH+DmM=",
	}

	err := encryptionService.SerializeSecret(&accessKey)

	if err != nil {
		t.Error(err)
	}

	//accessKey.ClearSecret()

	err = encryptionService.DeserializeSecret(&accessKey)

	if err != nil {
		t.Error(err)
	}

	if accessKey.SshKey.PrivateKey != "qerphqeruqoweurqwerqqeuiqwpavqr" {
		t.Error("invalid secret")
	}
}

func TestExternalSSHAgentSecretRoundTrip_NoEncryption(t *testing.T) {
	encryptionService := NewAccessKeyEncryptionService(nil, nil, nil, nil)

	util.Config = &util.ConfigType{}

	accessKey := db.AccessKey{
		Name: "ext-agent-key",
		Type: db.ExternalSshAgent,
		SSHExternalAgent: db.SSHExternalAgentConfig{
			Command: "/usr/local/bin/ssh-vend-local",
			Args:    []string{"semaphore-agent", "--principal", "ansadmin"},
			Config:  `{}`,
		},
	}

	err := encryptionService.SerializeSecret(&accessKey)
	if err != nil {
		t.Fatalf("SerializeSecret returned error: %v", err)
	}

	if accessKey.Secret == nil || *accessKey.Secret == "" {
		t.Fatal("expected non-empty serialized secret")
	}

	decoded, err := base64.StdEncoding.DecodeString(*accessKey.Secret)
	if err != nil {
		t.Fatalf("decode serialized secret: %v", err)
	}

	var gotCfg db.SSHExternalAgentConfig
	if err = json.Unmarshal(decoded, &gotCfg); err != nil {
		t.Fatalf("unmarshal serialized secret payload: %v", err)
	}

	if gotCfg.Command != accessKey.SSHExternalAgent.Command {
		t.Fatalf("command mismatch: got %q, want %q", gotCfg.Command, accessKey.SSHExternalAgent.Command)
	}

	if !reflect.DeepEqual(gotCfg.Args, accessKey.SSHExternalAgent.Args) {
		t.Fatalf("args mismatch: got %#v, want %#v", gotCfg.Args, accessKey.SSHExternalAgent.Args)
	}

	if gotCfg.Config != accessKey.SSHExternalAgent.Config {
		t.Fatalf("config mismatch: got %q, want %q", gotCfg.Config, accessKey.SSHExternalAgent.Config)
	}

	readBack := db.AccessKey{
		Type:   db.ExternalSshAgent,
		Secret: accessKey.Secret,
	}

	err = encryptionService.DeserializeSecret(&readBack)
	if err != nil {
		t.Fatalf("DeserializeSecret returned error: %v", err)
	}

	if readBack.SSHExternalAgent.Command != accessKey.SSHExternalAgent.Command {
		t.Fatalf("round-trip command mismatch: got %q, want %q", readBack.SSHExternalAgent.Command, accessKey.SSHExternalAgent.Command)
	}

	if !reflect.DeepEqual(readBack.SSHExternalAgent.Args, accessKey.SSHExternalAgent.Args) {
		t.Fatalf("round-trip args mismatch: got %#v, want %#v", readBack.SSHExternalAgent.Args, accessKey.SSHExternalAgent.Args)
	}

	if readBack.SSHExternalAgent.Config != accessKey.SSHExternalAgent.Config {
		t.Fatalf("round-trip config mismatch: got %q, want %q", readBack.SSHExternalAgent.Config, accessKey.SSHExternalAgent.Config)
	}
}

func TestExternalSSHAgentSecretRoundTrip_WithEncryption(t *testing.T) {
	encryptionService := NewAccessKeyEncryptionService(nil, nil, nil, nil)

	util.Config = &util.ConfigType{
		AccessKeyEncryption: "hHYgPrhQTZYm7UFTvcdNfKJMB3wtAXtJENUButH+DmM=",
	}

	accessKey := db.AccessKey{
		Name: "ext-agent-key",
		Type: db.ExternalSshAgent,
		SSHExternalAgent: db.SSHExternalAgentConfig{
			Command: "/usr/local/bin/ssh-vend-local",
			Args:    []string{"semaphore-agent", "--principal", "ansadmin"},
			Config:  `{}`,
		},
	}

	err := encryptionService.SerializeSecret(&accessKey)
	if err != nil {
		t.Fatalf("SerializeSecret returned error: %v", err)
	}

	if accessKey.Secret == nil || *accessKey.Secret == "" {
		t.Fatal("expected non-empty encrypted secret")
	}

	readBack := db.AccessKey{
		Type:   db.ExternalSshAgent,
		Secret: accessKey.Secret,
	}

	err = encryptionService.DeserializeSecret(&readBack)
	if err != nil {
		t.Fatalf("DeserializeSecret returned error: %v", err)
	}

	if readBack.SSHExternalAgent.Command != accessKey.SSHExternalAgent.Command {
		t.Fatalf("round-trip command mismatch: got %q, want %q", readBack.SSHExternalAgent.Command, accessKey.SSHExternalAgent.Command)
	}

	if !reflect.DeepEqual(readBack.SSHExternalAgent.Args, accessKey.SSHExternalAgent.Args) {
		t.Fatalf("round-trip args mismatch: got %#v, want %#v", readBack.SSHExternalAgent.Args, accessKey.SSHExternalAgent.Args)
	}

	if readBack.SSHExternalAgent.Config != accessKey.SSHExternalAgent.Config {
		t.Fatalf("round-trip config mismatch: got %q, want %q", readBack.SSHExternalAgent.Config, accessKey.SSHExternalAgent.Config)
	}
}

func TestExternalSSHAgentValidationMissingCommand(t *testing.T) {
	util.Config = &util.ConfigType{}
	encryptionService := NewAccessKeyEncryptionService(nil, nil, nil, nil)

	accessKey := db.AccessKey{
		Name: "ext-agent-key",
		Type: db.ExternalSshAgent,
		SSHExternalAgent: db.SSHExternalAgentConfig{
			Config: `{}`,
		},
	}

	err := encryptionService.SerializeSecret(&accessKey)
	if err == nil {
		t.Fatal("expected missing command validation error")
	}

	if !strings.Contains(err.Error(), "command") {
		t.Fatalf("expected error to mention command, got: %v", err)
	}
}

func TestExternalSSHAgentValidationMissingConfig(t *testing.T) {
	util.Config = &util.ConfigType{}
	encryptionService := NewAccessKeyEncryptionService(nil, nil, nil, nil)

	accessKey := db.AccessKey{
		Name: "ext-agent-key",
		Type: db.ExternalSshAgent,
		SSHExternalAgent: db.SSHExternalAgentConfig{
			Command: "/usr/local/bin/ssh-vend-local",
		},
	}

	err := encryptionService.SerializeSecret(&accessKey)
	if err == nil {
		t.Fatal("expected missing config validation error")
	}

	if !strings.Contains(err.Error(), "config") {
		t.Fatalf("expected error to mention config, got: %v", err)
	}
}

func TestExternalSSHAgentArgsString_NormalizedToSlice(t *testing.T) {
	util.Config = &util.ConfigType{}
	encryptionService := NewAccessKeyEncryptionService(nil, nil, nil, nil)

	var accessKey db.AccessKey
	err := json.Unmarshal([]byte(`{
		"name": "ext-agent-key",
		"type": "ssh_agent_external",
		"ssh_external_agent": {
			"command": "/usr/local/bin/ssh-vend-local",
			"args": "semaphore-agent -principal chrisp",
			"config": "{}"
		}
	}`), &accessKey)
	if err != nil {
		t.Fatalf("json unmarshal failed: %v", err)
	}

	expected := []string{"semaphore-agent", "-principal", "chrisp"}
	if !reflect.DeepEqual(accessKey.SSHExternalAgent.Args, expected) {
		t.Fatalf("normalized args mismatch: got %#v, want %#v", accessKey.SSHExternalAgent.Args, expected)
	}

	err = encryptionService.SerializeSecret(&accessKey)
	if err != nil {
		t.Fatalf("SerializeSecret returned error: %v", err)
	}

	readBack := db.AccessKey{Type: db.ExternalSshAgent, Secret: accessKey.Secret}
	err = encryptionService.DeserializeSecret(&readBack)
	if err != nil {
		t.Fatalf("DeserializeSecret returned error: %v", err)
	}

	if !reflect.DeepEqual(readBack.SSHExternalAgent.Args, expected) {
		t.Fatalf("round-trip args mismatch: got %#v, want %#v", readBack.SSHExternalAgent.Args, expected)
	}
}

func TestExternalSSHAgentArgsString_QuotedArguments(t *testing.T) {
	util.Config = &util.ConfigType{}

	var accessKey db.AccessKey
	err := json.Unmarshal([]byte(`{
		"name": "ext-agent-key",
		"type": "ssh_agent_external",
		"ssh_external_agent": {
			"command": "/usr/local/bin/ssh-vend-local",
			"args": "--label \"hello world\"",
			"config": "{}"
		}
	}`), &accessKey)
	if err != nil {
		t.Fatalf("json unmarshal failed: %v", err)
	}

	expected := []string{"--label", "hello world"}
	if !reflect.DeepEqual(accessKey.SSHExternalAgent.Args, expected) {
		t.Fatalf("quoted args mismatch: got %#v, want %#v", accessKey.SSHExternalAgent.Args, expected)
	}
}

func TestExternalSSHAgentArgsString_EmptyBecomesEmptySlice(t *testing.T) {
	util.Config = &util.ConfigType{}
	encryptionService := NewAccessKeyEncryptionService(nil, nil, nil, nil)

	var accessKey db.AccessKey
	err := json.Unmarshal([]byte(`{
		"name": "ext-agent-key",
		"type": "ssh_agent_external",
		"ssh_external_agent": {
			"command": "/usr/local/bin/ssh-vend-local",
			"args": "",
			"config": "{}"
		}
	}`), &accessKey)
	if err != nil {
		t.Fatalf("json unmarshal failed: %v", err)
	}

	if accessKey.SSHExternalAgent.Args == nil {
		t.Fatal("expected empty slice, got nil")
	}

	if len(accessKey.SSHExternalAgent.Args) != 0 {
		t.Fatalf("expected empty args slice, got %#v", accessKey.SSHExternalAgent.Args)
	}

	err = encryptionService.SerializeSecret(&accessKey)
	if err != nil {
		t.Fatalf("SerializeSecret returned error for empty args: %v", err)
	}

	readBack := db.AccessKey{Type: db.ExternalSshAgent, Secret: accessKey.Secret}
	err = encryptionService.DeserializeSecret(&readBack)
	if err != nil {
		t.Fatalf("DeserializeSecret returned error for empty args: %v", err)
	}

	if len(readBack.SSHExternalAgent.Args) != 0 {
		t.Fatalf("expected empty args slice after round-trip, got %#v", readBack.SSHExternalAgent.Args)
	}
}

func TestSerializeSecretReadOnlyReturnsUnwrappableSentinel(t *testing.T) {
	storageType := db.AccessKeySourceStorageEnv
	accessKey := db.AccessKey{
		Type:              db.AccessKeyString,
		Name:              "test",
		String:            "value",
		SourceStorageType: &storageType,
	}

	util.Config = &util.ConfigType{}
	encryptionService := NewAccessKeyEncryptionService(nil, nil, nil, nil)

	err := encryptionService.SerializeSecret(&accessKey)
	if err == nil {
		t.Fatal("expected error for read-only storage, got nil")
	}
	if !errors.Is(err, ErrReadOnlyStorage) {
		t.Fatalf("expected error to wrap ErrReadOnlyStorage, got: %v", err)
	}
}

func TestCreateSkipsSerializationForReadOnlyStorage(t *testing.T) {
	storageType := db.AccessKeySourceStorageEnv
	key := db.AccessKey{
		Type:              db.AccessKeyString,
		Name:              "test",
		String:            "value",
		SourceStorageType: &storageType,
	}

	util.Config = &util.ConfigType{}

	repo := &mockAccessKeyRepo{}
	encryptionService := NewAccessKeyEncryptionService(nil, nil, nil, nil)
	svc := NewAccessKeyService(repo, encryptionService, nil)

	created, err := svc.Create(key)
	if err != nil {
		t.Fatalf("Create should succeed for read-only storage, got: %v", err)
	}
	if created.Name != "test" {
		t.Fatalf("expected key name 'test', got '%s'", created.Name)
	}
}

func TestRekeyAccessKeysSkipsExternalStorageKeys(t *testing.T) {
	vaultType := db.AccessKeySourceStorageVault
	envType := db.AccessKeySourceStorageEnv
	fileType := db.AccessKeySourceStorageFile
	projectID := 1

	localSecret := base64.StdEncoding.EncodeToString([]byte("local-secret-value"))
	vaultSecret := "vault-ciphertext-should-not-be-touched"
	envSecret := "env-ciphertext-should-not-be-touched"
	fileSecret := "file-ciphertext-should-not-be-touched"

	allKeys := []db.AccessKey{
		{
			ID:        1,
			Name:      "local-key",
			Type:      db.AccessKeyString,
			ProjectID: &projectID,
			Secret:    &localSecret,
		},
		{
			ID:                2,
			Name:              "vault-key",
			Type:              db.AccessKeyString,
			ProjectID:         &projectID,
			Secret:            &vaultSecret,
			SourceStorageType: &vaultType,
			SourceStorageID:   intPtr(10),
		},
		{
			ID:                3,
			Name:              "env-key",
			Type:              db.AccessKeyString,
			ProjectID:         &projectID,
			Secret:            &envSecret,
			SourceStorageType: &envType,
			SourceStorageKey:  strPtr("MY_ENV_VAR"),
		},
		{
			ID:                4,
			Name:              "file-key",
			Type:              db.AccessKeyString,
			ProjectID:         &projectID,
			Secret:            &fileSecret,
			SourceStorageType: &fileType,
			SourceStorageKey:  strPtr("/etc/secret"),
		},
	}

	var updatedIDs []int
	keyMgr := &mockAccessKeyManager{
		GetAccessKeysFn: func(_ int, _ db.GetAccessKeyOptions, params db.RetrieveQueryParams) ([]db.AccessKey, error) {
			if params.Offset > 0 {
				return nil, nil
			}
			return allKeys, nil
		},
		UpdateAccessKeyFn: func(key db.AccessKey) error {
			updatedIDs = append(updatedIDs, key.ID)
			return nil
		},
	}

	projectStore := &mockProjectStore{
		GetAllProjectsFn: func() ([]db.Project, error) {
			return []db.Project{{ID: projectID}}, nil
		},
	}

	util.Config = &util.ConfigType{}
	svc := NewAccessKeyEncryptionService(keyMgr, nil, nil, projectStore)

	err := svc.RekeyAccessKeys("")
	if err != nil {
		t.Fatalf("RekeyAccessKeys returned error: %v", err)
	}

	if len(updatedIDs) != 1 || updatedIDs[0] != 1 {
		t.Fatalf("expected only local key (ID=1) to be updated, got updates for IDs: %v", updatedIDs)
	}
}

func intPtr(i int) *int       { return &i }
func strPtr(s string) *string { return &s }

type mockAccessKeyRepo struct {
	keys []db.AccessKey
}

func (m *mockAccessKeyRepo) GetAccessKey(_ int, keyID int) (db.AccessKey, error) {
	for _, k := range m.keys {
		if k.ID == keyID {
			return k, nil
		}
	}
	return db.AccessKey{}, db.ErrNotFound
}
func (m *mockAccessKeyRepo) GetAccessKeyRefs(int, int) (db.ObjectReferrers, error) {
	return db.ObjectReferrers{}, nil
}
func (m *mockAccessKeyRepo) GetAccessKeys(int, db.GetAccessKeyOptions, db.RetrieveQueryParams) ([]db.AccessKey, error) {
	return nil, nil
}
func (m *mockAccessKeyRepo) UpdateAccessKey(db.AccessKey) error { return nil }
func (m *mockAccessKeyRepo) CreateAccessKey(k db.AccessKey) (db.AccessKey, error) {
	return k, nil
}
func (m *mockAccessKeyRepo) DeleteAccessKey(int, int) error { return nil }
