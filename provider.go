package main

import (
	"github.com/FranckSallet/tf-windows/internal/windows"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func Provider() *schema.Provider {
	return &schema.Provider{
		ResourcesMap: map[string]*schema.Resource{
			"tf-windows_feature": windows.ResourceWindowsFeature(),
		},
	}
}
