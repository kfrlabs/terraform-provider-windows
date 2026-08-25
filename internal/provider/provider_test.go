// Package provider — unit tests for the provider entrypoint (provider.go).
//
// These tests exercise Metadata, Schema, Resources, DataSources, pathAttr and
// the Configure handler. Configure is driven with a tfsdk.Config built from a
// tftypes.Value to cover both error paths (missing credentials, invalid
// timeout) and the happy path (a fully populated config that constructs a
// *winclient.Client).
package provider

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
	"golang.org/x/crypto/ssh"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

func TestProvider_New(t *testing.T) {
	ctor := New("test-version")
	if ctor == nil {
		t.Fatal("New returned nil constructor")
	}
	p := ctor()
	if p == nil {
		t.Fatal("constructor returned nil provider")
	}
}

func TestProvider_Metadata(t *testing.T) {
	p := &windowsProvider{version: "v0"}
	resp := &provider.MetadataResponse{}
	p.Metadata(context.Background(), provider.MetadataRequest{}, resp)
	if resp.TypeName != "windows" {
		t.Errorf("TypeName = %q", resp.TypeName)
	}
	if resp.Version != "v0" {
		t.Errorf("Version = %q", resp.Version)
	}
}

func TestProvider_Schema(t *testing.T) {
	p := &windowsProvider{}
	resp := &provider.SchemaResponse{}
	p.Schema(context.Background(), provider.SchemaRequest{}, resp)
	for _, k := range []string{"host", "port", "username", "password", "timeout"} {
		if _, ok := resp.Schema.Attributes[k]; !ok {
			t.Errorf("provider schema missing %q", k)
		}
	}
}

func TestProvider_ResourcesAndDataSources(t *testing.T) {
	p := &windowsProvider{}
	if got := len(p.Resources(context.Background())); got != 12 {
		t.Errorf("Resources len = %d, want 12 (service + feature + hostname + local_group + local_group_member + local_user + registry_value + environment_variable + scheduled_task + firewall_rule + winget_package + legacy_package)", got)
	}
	if got := len(p.DataSources(context.Background())); got != 11 {
		t.Errorf("DataSources len = %d, want 11 (feature + hostname + local_group + local_group_member + local_user + registry_value + service + environment_variable + scheduled_task + firewall_rule + winget_package)", got)
	}
}

func TestPathAttr(t *testing.T) {
	if p := pathAttr("host"); p.String() == "" {
		t.Error("pathAttr should produce a non-empty Path")
	}
}

// providerConfigObjectType matches the provider schema.
func providerConfigObjectType() tftypes.Object {
	return tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"host":                     tftypes.String,
		"port":                     tftypes.Number,
		"username":                 tftypes.String,
		"password":                 tftypes.String,
		"timeout":                  tftypes.String,
		"private_key":              tftypes.String,
		"private_key_path":         tftypes.String,
		"private_key_passphrase":   tftypes.String,
		"use_agent":                tftypes.Bool,
		"known_hosts_path":         tftypes.String,
		"host_key":                 tftypes.String,
		"insecure_ignore_host_key": tftypes.Bool,
	}}
}

// providerCfgOptions mirrors the provider attributes a test wants to set; a
// nil field is a null attribute.
type providerCfgOptions struct {
	host                  *string
	username              *string
	password              *string
	timeout               *string
	privateKey            *string
	privateKeyPath        *string
	privateKeyPassphrase  *string
	useAgent              *bool
	knownHostsPath        *string
	hostKey               *string
	insecureIgnoreHostKey *bool
}

func providerCfgValue(o providerCfgOptions) tftypes.Value {
	s := func(p *string) tftypes.Value {
		if p == nil {
			return tftypes.NewValue(tftypes.String, nil)
		}
		return tftypes.NewValue(tftypes.String, *p)
	}
	b := func(p *bool) tftypes.Value {
		if p == nil {
			return tftypes.NewValue(tftypes.Bool, nil)
		}
		return tftypes.NewValue(tftypes.Bool, *p)
	}
	return tftypes.NewValue(providerConfigObjectType(), map[string]tftypes.Value{
		"host":                     s(o.host),
		"port":                     tftypes.NewValue(tftypes.Number, nil),
		"username":                 s(o.username),
		"password":                 s(o.password),
		"timeout":                  s(o.timeout),
		"private_key":              s(o.privateKey),
		"private_key_path":         s(o.privateKeyPath),
		"private_key_passphrase":   s(o.privateKeyPassphrase),
		"use_agent":                b(o.useAgent),
		"known_hosts_path":         s(o.knownHostsPath),
		"host_key":                 s(o.hostKey),
		"insecure_ignore_host_key": b(o.insecureIgnoreHostKey),
	})
}

// clearProviderEnv keeps the ambient environment from leaking into a test:
// every provider attribute has an env fallback, including the host-key ones.
func clearProviderEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		winclient.EnvHost, winclient.EnvUsername, winclient.EnvPassword,
		winclient.EnvPrivateKey, winclient.EnvPrivateKeyPath, winclient.EnvPrivateKeyPassphrase,
		winclient.EnvUseAgent, winclient.EnvKnownHosts, winclient.EnvHostKey,
		winclient.EnvInsecureIgnoreHostKey,
	} {
		t.Setenv(k, "")
	}
	t.Setenv("SSH_AUTH_SOCK", "")
}

// testHostKey returns an ed25519 public key in authorized_keys form, suitable
// for the host_key attribute.
func testHostKey(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("wrap key: %v", err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))
}

func configureProvider(t *testing.T, o providerCfgOptions) *provider.ConfigureResponse {
	t.Helper()
	p := &windowsProvider{}
	schemaResp := &provider.SchemaResponse{}
	p.Schema(context.Background(), provider.SchemaRequest{}, schemaResp)

	cfg := tfsdk.Config{Schema: schemaResp.Schema, Raw: providerCfgValue(o)}
	resp := &provider.ConfigureResponse{}
	p.Configure(context.Background(), provider.ConfigureRequest{Config: cfg}, resp)
	return resp
}

func strPtr(s string) *string { return &s }
func boolPtr(b bool) *bool    { return &b }

// TestProvider_Configure_HappyPath covers the full success path: credentials
// plus a pinned host key; the response gets a non-nil ResourceData (our
// *winclient.Client).
func TestProvider_Configure_HappyPath(t *testing.T) {
	clearProviderEnv(t)

	resp := configureProvider(t, providerCfgOptions{
		host:     strPtr("10.0.0.1"),
		username: strPtr("admin"),
		password: strPtr("secret"),
		timeout:  strPtr("15s"),
		hostKey:  strPtr(testHostKey(t)),
	})
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diags: %v", resp.Diagnostics)
	}
	if resp.ResourceData == nil || resp.DataSourceData == nil {
		t.Error("Configure should populate ResourceData and DataSourceData")
	}
}

// Key-based auth with no password at all must configure cleanly: the password
// is no longer a required attribute.
func TestProvider_Configure_KeyOnly(t *testing.T) {
	clearProviderEnv(t)

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	block, err := ssh.MarshalPrivateKey(&priv, "")
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}

	resp := configureProvider(t, providerCfgOptions{
		host:       strPtr("10.0.0.1"),
		username:   strPtr("admin"),
		privateKey: strPtr(string(pem.EncodeToMemory(block))),
		hostKey:    strPtr(testHostKey(t)),
	})
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diags: %v", resp.Diagnostics)
	}
	if resp.ResourceData == nil {
		t.Error("Configure should populate ResourceData")
	}
}

func TestProvider_Configure_MissingCredentials(t *testing.T) {
	clearProviderEnv(t)

	resp := configureProvider(t, providerCfgOptions{})
	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error diags for missing host/user/credentials")
	}
}

// Credentials present but no way to establish who the server is: the provider
// must refuse rather than connect blindly.
func TestProvider_Configure_FailsClosedWithoutHostVerification(t *testing.T) {
	clearProviderEnv(t)
	t.Setenv("HOME", t.TempDir())

	resp := configureProvider(t, providerCfgOptions{
		host:     strPtr("10.0.0.1"),
		username: strPtr("admin"),
		password: strPtr("secret"),
	})
	if !resp.Diagnostics.HasError() {
		t.Fatal("expected an error when the host key cannot be verified")
	}
}

// The opt-out must work, and must be impossible to take silently.
func TestProvider_Configure_InsecureOptOutWarns(t *testing.T) {
	clearProviderEnv(t)

	resp := configureProvider(t, providerCfgOptions{
		host:                  strPtr("10.0.0.1"),
		username:              strPtr("admin"),
		password:              strPtr("secret"),
		insecureIgnoreHostKey: boolPtr(true),
	})
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diags: %v", resp.Diagnostics)
	}
	if resp.Diagnostics.WarningsCount() == 0 {
		t.Fatal("disabling host key verification must emit a warning")
	}
	if resp.ResourceData == nil {
		t.Error("Configure should still populate ResourceData")
	}
}

// Ambiguous host-key configuration is rejected rather than resolved by
// silent precedence.
func TestProvider_Configure_RejectsConflictingHostKeyOptions(t *testing.T) {
	clearProviderEnv(t)

	resp := configureProvider(t, providerCfgOptions{
		host:           strPtr("10.0.0.1"),
		username:       strPtr("admin"),
		password:       strPtr("secret"),
		hostKey:        strPtr(testHostKey(t)),
		knownHostsPath: strPtr("/etc/ssh/known_hosts"),
	})
	if !resp.Diagnostics.HasError() {
		t.Fatal("host_key combined with known_hosts_path should be rejected")
	}
}

// Env fallbacks must cover the new attributes, since acceptance tests and CI
// configure the provider entirely through the environment.
func TestProvider_Configure_HostKeyFromEnv(t *testing.T) {
	clearProviderEnv(t)
	t.Setenv("HOME", t.TempDir())
	t.Setenv(winclient.EnvHostKey, testHostKey(t))

	resp := configureProvider(t, providerCfgOptions{
		host:     strPtr("10.0.0.1"),
		username: strPtr("admin"),
		password: strPtr("secret"),
	})
	if resp.Diagnostics.HasError() {
		t.Fatalf("WINDOWS_HOST_KEY should satisfy host verification, got: %v", resp.Diagnostics)
	}
}

func TestProvider_Configure_InvalidTimeout(t *testing.T) {
	clearProviderEnv(t)

	resp := configureProvider(t, providerCfgOptions{
		host:     strPtr("x"),
		username: strPtr("u"),
		password: strPtr("p"),
		timeout:  strPtr("not-a-duration"),
		hostKey:  strPtr(testHostKey(t)),
	})
	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error diag for invalid timeout")
	}
}
