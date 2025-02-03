package main

import (
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/plugin"

	"terraform-provider-appviewx/appviewx"
)

var (
	version     string = "1.0.1"
	releaseDate string = "Feb 1 2025"
)

func init() {
	log.Println("[INFO] version", version)
	log.Println("[INFO] releaseDate", releaseDate)
}

func main() {
	plugin.Serve(&plugin.ServeOpts{
		ProviderFunc: func() *schema.Provider {
			return appviewx.Provider()
		},
	})
}
