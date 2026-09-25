package main

import (
	"log"
	"os"

	"github.com/rlwillen0121/identity-mcp/internal/c1"
	"github.com/rlwillen0121/identity-mcp/internal/idmcp"
)

func main() {
	log.SetOutput(os.Stderr)
	log.SetFlags(0)
	idmcp.MustEnv("C1_CLIENT_ID", "C1_CLIENT_SECRET")
	base, tokenURL, err := c1.ResolveEndpoints(os.Getenv("C1_CLIENT_ID"), os.Getenv("C1_BASE_URL"), os.Getenv("C1_TOKEN_URL"))
	if err != nil {
		log.Fatal(err)
	}
	client := c1.NewClient(c1.Config{
		ClientID:     os.Getenv("C1_CLIENT_ID"),
		ClientSecret: os.Getenv("C1_CLIENT_SECRET"),
		BaseURL:      base,
		TokenURL:     tokenURL,
	})
	idmcp.RunStdio(c1.NewServer(client))
}
