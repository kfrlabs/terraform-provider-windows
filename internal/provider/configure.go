// Shared Configure helper for resources and data sources.
//
// Every resource/data source receives the same ProviderData (the shared
// *winclient.Client built by the provider Configure) and performs the same
// nil/type check before wrapping it in its specific client. The helper
// keeps those 70 identical copies in one place so the diagnostic text
// cannot drift again.
package provider

import (
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/diag"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

// configuredClient extracts the shared *winclient.Client from ProviderData.
//
// A nil ProviderData is not an error (the framework calls Configure before
// ProviderData is set); it returns nil with no diagnostic. A ProviderData
// of the wrong type appends an "Unexpected provider data type" diagnostic
// and returns nil. Callers return early on nil:
//
//	c := configuredClient(req.ProviderData, &resp.Diagnostics)
//	if c == nil {
//		return
//	}
func configuredClient(providerData any, diags *diag.Diagnostics) *winclient.Client {
	if providerData == nil {
		return nil
	}
	c, ok := providerData.(*winclient.Client)
	if !ok {
		diags.AddError(
			"Unexpected provider data type",
			fmt.Sprintf("Expected *winclient.Client, got %T", providerData),
		)
		return nil
	}
	return c
}
