package main

import (
	"fmt"
	"os"

	"github.com/rlwillen0121/identity-mcp/internal/entra"
	"github.com/rlwillen0121/identity-mcp/internal/idmcp"
)

func main() {
	idmcp.MustEnv("AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET")
	graphBase := os.Getenv("GRAPH_BASE_URL")
	if graphBase == "" {
		graphBase = "https://graph.microsoft.com/v1.0"
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
