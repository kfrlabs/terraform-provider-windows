// Package provider — regression tests for issue #195.
//
// Secrets on windows_local_user, windows_service and windows_scheduled_task
// are streamed over stdin and consumed with [Console]::In.ReadLine(). A
// value containing \r or \n would be silently truncated at the first line
// break, so every secret attribute carries secretNoLineBreakValidator at
// plan time. These tests assert the validator behaviour directly and that
// each of the six secret attributes wires it into its schema.
package provider

import (
	"context"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// secretAcceptValues are representative secrets that must pass: plain,
// unicode, spaces and symbols — none of which contain line breaks.
var secretAcceptValues = []string{
	"P@ssw0rd!",
	"correct horse battery staple",
	"Pässwörd-日本語-123!@#$%",
	"  leading-and-trailing-spaces  ",
	"tab\tseparated",
	"symbols: ~`!@#$%^&*()_+-=[]{}|;':\",./<>?",
}

// secretRejectValues are secrets that must fail: embedded LF, CR, CRLF and
// a trailing newline (the file() footgun).
var secretRejectValues = []string{
	"a\nb",
	"a\rb",
	"a\r\nb",
	"secret\n",
}

func runSecretValidators(t *testing.T, p path.Path, value types.String, validators []validator.String) validator.StringResponse {
	t.Helper()
	req := validator.StringRequest{
		Path:        p,
		ConfigValue: value,
	}
	resp := &validator.StringResponse{}
	for _, v := range validators {
		v.ValidateString(context.Background(), req, resp)
		if resp.Diagnostics.HasError() {
			break
		}
	}
	return *resp
}

func TestSecretNoLineBreakValidator_Accepts(t *testing.T) {
	v := secretNoLineBreakValidator{}
	for _, tc := range secretAcceptValues {
		resp := &validator.StringResponse{}
		v.ValidateString(context.Background(), validator.StringRequest{
			Path:        path.Root("password"),
			ConfigValue: types.StringValue(tc),
		}, resp)
		if resp.Diagnostics.HasError() {
			t.Errorf("value %q must be accepted", tc)
		}
	}
}

func TestSecretNoLineBreakValidator_Rejects(t *testing.T) {
	v := secretNoLineBreakValidator{}
	for _, tc := range secretRejectValues {
		resp := &validator.StringResponse{}
		v.ValidateString(context.Background(), validator.StringRequest{
			Path:        path.Root("password"),
			ConfigValue: types.StringValue(tc),
		}, resp)
		if !resp.Diagnostics.HasError() {
			t.Errorf("value %q must be rejected", tc)
		}
	}
}

func TestSecretNoLineBreakValidator_SkipsNullAndUnknown(t *testing.T) {
	v := secretNoLineBreakValidator{}
	for name, val := range map[string]types.String{
		"null":    types.StringNull(),
		"unknown": types.StringUnknown(),
	} {
		resp := &validator.StringResponse{}
		v.ValidateString(context.Background(), validator.StringRequest{
			Path:        path.Root("password"),
			ConfigValue: val,
		}, resp)
		if resp.Diagnostics.HasError() {
			t.Errorf("%s value must be skipped", name)
		}
	}
}

func TestSecretNoLineBreakValidator_DiagnosticSuggestsTrimspace(t *testing.T) {
	v := secretNoLineBreakValidator{}
	resp := &validator.StringResponse{}
	v.ValidateString(context.Background(), validator.StringRequest{
		Path:        path.Root("password"),
		ConfigValue: types.StringValue("a\nb"),
	}, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("expected error diagnostic")
	}
	detail := resp.Diagnostics[0].Detail()
	if !strings.Contains(detail, "trimspace()") {
		t.Errorf("diagnostic must suggest trimspace(), got: %q", detail)
	}
	// The secret value itself must never be echoed back (Sensitive).
	if strings.Contains(detail, "a\nb") {
		t.Errorf("diagnostic must not echo the secret value, got: %q", detail)
	}
}

func TestSecretNoLineBreakValidator_Description(t *testing.T) {
	v := secretNoLineBreakValidator{}
	if v.Description(context.Background()) == "" {
		t.Error("Description must not be empty")
	}
	if v.MarkdownDescription(context.Background()) == "" {
		t.Error("MarkdownDescription must not be empty")
	}
}

// secretAttrValidators extracts the string validators of a top-level
// attribute from a resource schema, failing the test on shape mismatches.
func secretAttrValidators(t *testing.T, s schema.Schema, attrName string) []validator.String {
	t.Helper()
	attr, ok := s.Attributes[attrName].(schema.StringAttribute)
	if !ok {
		t.Fatalf("attribute %q is not a StringAttribute", attrName)
	}
	return attr.Validators
}

func assertSecretAttrGuarded(t *testing.T, attrPath path.Path, validators []validator.String) {
	t.Helper()
	var guarded []validator.String
	for _, v := range validators {
		if _, ok := v.(secretNoLineBreakValidator); ok {
			guarded = append(guarded, v)
		}
	}
	if len(guarded) == 0 {
		t.Fatalf("attribute %s does not wire secretNoLineBreakValidator", attrPath)
	}
	// Only the line-break validators run here: sibling validators (e.g. the
	// AlsoRequires on service_password_wo) need a full tfsdk.Config and are
	// covered by their own resource tests.
	for _, tc := range secretAcceptValues {
		resp := runSecretValidators(t, attrPath, types.StringValue(tc), guarded)
		if resp.Diagnostics.HasError() {
			t.Errorf("attribute %s must accept %q", attrPath, tc)
		}
	}
	for _, tc := range secretRejectValues {
		resp := runSecretValidators(t, attrPath, types.StringValue(tc), guarded)
		if !resp.Diagnostics.HasError() {
			t.Errorf("attribute %s must reject %q", attrPath, tc)
		}
	}
}

func TestLocalUserPassword_NoLineBreak(t *testing.T) {
	s := windowsLocalUserSchemaDefinition(context.Background())
	assertSecretAttrGuarded(t, path.Root("password"), secretAttrValidators(t, s, "password"))
}

func TestLocalUserPasswordWo_NoLineBreak(t *testing.T) {
	s := windowsLocalUserSchemaDefinition(context.Background())
	assertSecretAttrGuarded(t, path.Root("password_wo"), secretAttrValidators(t, s, "password_wo"))
}

func TestServicePassword_NoLineBreak(t *testing.T) {
	s := windowsServiceSchemaDefinition(context.Background())
	assertSecretAttrGuarded(t, path.Root("service_password"), secretAttrValidators(t, s, "service_password"))
}

func TestServicePasswordWo_NoLineBreak(t *testing.T) {
	s := windowsServiceSchemaDefinition(context.Background())
	assertSecretAttrGuarded(t, path.Root("service_password_wo"), secretAttrValidators(t, s, "service_password_wo"))
}

// scheduledTaskPrincipalValidators extracts the string validators of a
// nested principal attribute from the windows_scheduled_task schema.
func scheduledTaskPrincipalValidators(t *testing.T, attrName string) []validator.String {
	t.Helper()
	r := &windowsScheduledTaskResource{}
	resp := &resource.SchemaResponse{}
	r.Schema(context.Background(), resource.SchemaRequest{}, resp)
	principal, ok := resp.Schema.Attributes["principal"].(schema.SingleNestedAttribute)
	if !ok {
		t.Fatal("principal is not a SingleNestedAttribute")
	}
	attr, ok := principal.Attributes[attrName].(schema.StringAttribute)
	if !ok {
		t.Fatalf("principal.%s is not a StringAttribute", attrName)
	}
	return attr.Validators
}

func TestScheduledTaskPrincipalPassword_NoLineBreak(t *testing.T) {
	assertSecretAttrGuarded(t,
		path.Root("principal").AtName("password"),
		scheduledTaskPrincipalValidators(t, "password"))
}

func TestScheduledTaskPrincipalPasswordWo_NoLineBreak(t *testing.T) {
	assertSecretAttrGuarded(t,
		path.Root("principal").AtName("password_wo"),
		scheduledTaskPrincipalValidators(t, "password_wo"))
}
