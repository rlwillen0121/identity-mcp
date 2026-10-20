//go:build !unix

package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "mcp-authz-gateway: unsupported platform (requires darwin or linux)")
	os.Exit(1)
}
