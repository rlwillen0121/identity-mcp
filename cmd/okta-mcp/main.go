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
	header := make(http.Header)
	header.Set("Authorization", "SSWS "+os.Getenv("OKTA_API_TOKEN"))
	client := idmcp.NewClient(os.Getenv("OKTA_ORG_URL"), header)
	idmcp.RunStdio(okta.NewServer(client))
}
