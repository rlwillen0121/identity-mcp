package main

import (
	"log"
	"net/http"
	"os"

	"github.com/rlwillen0121/identity-mcp/internal/idmcp"
	"github.com/rlwillen0121/identity-mcp/internal/okta"
)

func main() {
	log.SetOutput(os.Stderr)
	log.SetFlags(0)
	idmcp.MustEnv("OKTA_ORG_URL", "OKTA_API_TOKEN")
	org := os.Getenv("OKTA_ORG_URL")
	if err := idmcp.RequireHTTPS("OKTA_ORG_URL", org); err != nil {
		log.Fatal(err)
	}
	header := make(http.Header)
	header.Set("Authorization", "SSWS "+os.Getenv("OKTA_API_TOKEN"))
	client := idmcp.NewClient(org, header)
	idmcp.RunStdio(okta.NewServer(client))
}
