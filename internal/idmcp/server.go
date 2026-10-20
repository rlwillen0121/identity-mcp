package idmcp

import (
	"context"
	"log"
	"os"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func NewServer(name, version string) *mcp.Server {
	return mcp.NewServer(&mcp.Implementation{Name: name, Version: version}, nil)
}

// WritesEnabled returns true when --enable-writes is passed on the command line
// or IDENTITY_MCP_ENABLE_WRITES is set to "1" or "true".
func WritesEnabled(args []string) bool {
	for _, a := range args {
		if a == "--enable-writes" || a == "-enable-writes" {
			return true
		}
	}
	v := strings.TrimSpace(strings.ToLower(os.Getenv("IDENTITY_MCP_ENABLE_WRITES")))
	return v == "1" || v == "true"
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
