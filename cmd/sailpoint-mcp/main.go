package main

import (
	"log"
	"os"

	"github.com/rlwillen0121/identity-mcp/internal/idmcp"
	"github.com/rlwillen0121/identity-mcp/internal/sailpoint"
)

func main() {
	log.SetOutput(os.Stderr)
	log.SetFlags(0)
	idmcp.MustEnv("SAILPOINT_CLIENT_ID", "SAILPOINT_CLIENT_SECRET")
	base, tokenURL, err := sailpoint.Endpoints(os.Getenv("SAILPOINT_TENANT"), os.Getenv("SAILPOINT_BASE_URL"), os.Getenv("SAILPOINT_TOKEN_URL"))
	if err != nil {
		log.Fatal(err)
	}
	client := sailpoint.NewClient(sailpoint.Config{
		ClientID:     os.Getenv("SAILPOINT_CLIENT_ID"),
		ClientSecret: os.Getenv("SAILPOINT_CLIENT_SECRET"),
		BaseURL:      base,
		TokenURL:     tokenURL,
	})
	idmcp.RunStdio(sailpoint.NewServer(client))
}
