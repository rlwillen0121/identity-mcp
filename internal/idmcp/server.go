package idmcp

import (
	"context"
	"log"
	"os"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func NewServer(name, version string) *mcp.Server {
	return mcp.NewServer(&mcp.Implementation{Name: name, Version: version}, nil)
}

func RunStdio(server *mcp.Server) {
	log.SetOutput(os.Stderr)
	log.SetFlags(0)
	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatal(err)
	}
}

func MustEnv(keys ...string) {
	var missing []string
	for _, k := range keys {
		if os.Getenv(k) == "" {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		log.Fatalf("missing required environment: %v", missing)
	}
}
