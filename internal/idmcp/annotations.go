package idmcp

import "github.com/modelcontextprotocol/go-sdk/mcp"

func boolPtr(v bool) *bool { return &v }

// ReadOnly annotates a tool that only reads identity data from an external IdP.
func ReadOnly(title string) *mcp.ToolAnnotations {
	return &mcp.ToolAnnotations{
		Title:          title,
		ReadOnlyHint:   true,
		IdempotentHint: true,
		OpenWorldHint:  boolPtr(true),
	}
}
