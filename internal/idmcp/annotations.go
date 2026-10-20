package idmcp

import "github.com/modelcontextprotocol/go-sdk/mcp"

func boolPtr(v bool) *bool { return &v }

// ReadOnly annotates a tool that only reads identity data from an external IdP.
func ReadOnly(title string) *mcp.ToolAnnotations {
	return &mcp.ToolAnnotations{
		Title:           title,
		ReadOnlyHint:    true,
		DestructiveHint: boolPtr(false),
		IdempotentHint:  true,
		OpenWorldHint:   boolPtr(true),
	}
}

// Write annotates an opt-in mutating tool (registered only when writes are enabled).
func Write(title string, idempotent, destructive bool) *mcp.ToolAnnotations {
	return &mcp.ToolAnnotations{
		Title:           title,
		ReadOnlyHint:    false,
		DestructiveHint: boolPtr(destructive),
		IdempotentHint:  idempotent,
		OpenWorldHint:   boolPtr(true),
	}
}
