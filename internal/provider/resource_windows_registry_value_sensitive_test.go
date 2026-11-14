// Package provider — regression test: value_strings is Sensitive (campaign).
//
// value_string and value_binary were already Sensitive; value_strings
// (REG_MULTI_SZ) carries the same secret risk and must be masked too.
package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
)

func TestRegistryValueSchema_ValueStringsIsSensitive(t *testing.T) {
	s := windowsRegistryValueSchemaDefinition(context.Background())
	a, ok := s.Attributes["value_strings"].(schema.ListAttribute)
	if !ok {
		t.Fatalf("value_strings is not a ListAttribute, got %T", s.Attributes["value_strings"])
	}
	if !a.Sensitive {
		t.Error("value_strings must be Sensitive (REG_MULTI_SZ may carry secrets)")
	}
	// Siblings stay Sensitive.
	for _, n := range []string{"value_string", "value_binary"} {
		sa, ok := s.Attributes[n].(schema.StringAttribute)
		if !ok {
			t.Fatalf("%s is not a StringAttribute, got %T", n, s.Attributes[n])
		}
		if !sa.Sensitive {
			t.Errorf("%s must remain Sensitive", n)
		}
	}
}
