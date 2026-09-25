package main

import (
	"log"
	"net/http"
	"os"

	"github.com/rlwillen0121/identity-mcp/internal/idmcp"
	"github.com/rlwillen0121/identity-mcp/internal/lumos"
)

func main() {
	log.SetOutput(os.Stderr)
	log.SetFlags(0)
	idmcp.MustEnv("LUMOS_API_TOKEN")
	base := os.Getenv("LUMOS_BASE_URL")
	if base == "" {
		base = "https://api.lumos.com"
	}
	if err := idmcp.RequireHTTPS("LUMOS_BASE_URL", base); err != nil {
		log.Fatal(err)
	}
	header := make(http.Header)
	header.Set("Authorization", "Bearer "+os.Getenv("LUMOS_API_TOKEN"))
	header.Set("Accept", "application/json")
	client := idmcp.NewClient(base, header)
	idmcp.RunStdio(lumos.NewServer(client))
}
