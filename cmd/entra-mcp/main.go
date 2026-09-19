package main

import (
	"fmt"
	"log"
	"os"

	"github.com/rlwillen0121/identity-mcp/internal/entra"
	"github.com/rlwillen0121/identity-mcp/internal/idmcp"
)

func main() {
	log.SetOutput(os.Stderr)
	log.SetFlags(0)
	idmcp.MustEnv("AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET")
	graphBase := os.Getenv("GRAPH_BASE_URL")
	if graphBase == "" {
		graphBase = "https://graph.microsoft.com/v1.0"
	}
	if err := idmcp.RequireHTTPS("GRAPH_BASE_URL", graphBase); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	tenant := os.Getenv("AZURE_TENANT_ID")
	client := entra.NewClient(entra.Config{
		TenantID:     tenant,
		ClientID:     os.Getenv("AZURE_CLIENT_ID"),
		ClientSecret: os.Getenv("AZURE_CLIENT_SECRET"),
		GraphBaseURL: graphBase,
		TokenURL:     fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", tenant),
	})
	idmcp.RunStdio(entra.NewServer(client))
}
