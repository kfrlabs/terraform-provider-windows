// Package provider — shared test helpers for data source `timeouts` blocks.
//
// Issue #197 bounds every data source Read with a `timeouts.read` value from
// terraform-plugin-framework-timeouts/datasource/timeouts. The helpers here
// build the raw tftypes fragments that the per-data-source config
// constructors embed, so unit tests can assert schema presence, null-block
// defaulting and deadline propagation without SSH.
package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// dsTimeoutsObjType is the tftypes shape of the data source `timeouts`
// block: a single optional `read` duration string.
func dsTimeoutsObjType() tftypes.Object {
	return tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"read": tftypes.String,
	}}
}

// dsNullTimeoutsValue is the absent-block value embedded in data source test
// configs. Decoding yields a null timeouts object, and Value.Read then falls
// back to the per-data-source default (issue #197: a data source config may
// omit the block).
func dsNullTimeoutsValue() tftypes.Value {
	return tftypes.NewValue(dsTimeoutsObjType(), nil)
}

// dsTimeoutsValueWithRead builds a `timeouts` block value carrying read=d
// (a Go duration string such as "45s").
func dsTimeoutsValueWithRead(d string) tftypes.Value {
	return tftypes.NewValue(dsTimeoutsObjType(), map[string]tftypes.Value{
		"read": tftypes.NewValue(tftypes.String, d),
	})
}

// dsConfigWithReadTimeout returns cfg with the `timeouts` block set to
// read=d, preserving every other configured attribute.
func dsConfigWithReadTimeout(t *testing.T, cfg tfsdk.Config, d string) tfsdk.Config {
	t.Helper()
	var vals map[string]tftypes.Value
	if err := cfg.Raw.As(&vals); err != nil {
		t.Fatalf("config Raw.As: %v", err)
	}
	vals["timeouts"] = dsTimeoutsValueWithRead(d)
	objType, ok := cfg.Raw.Type().(tftypes.Object)
	if !ok {
		t.Fatalf("config Raw type is %T, want tftypes.Object", cfg.Raw.Type())
	}
	cfg.Raw = tftypes.NewValue(objType, vals)
	return cfg
}
