package idmcp

import (
	"encoding/json"
	"fmt"
	"strings"
)

type Page[T any] struct {
	Items     []T    `json:"items" jsonschema:"result items"`
	Next      string `json:"next,omitempty" jsonschema:"opaque cursor for the next page"`
	Truncated bool   `json:"truncated,omitempty" jsonschema:"true if more results exist beyond this page"`
}

func Marshal(v any) (string, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal result: %w", err)
	}
	return string(b), nil
}

func Require(name, value string) error {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return fmt.Errorf("%s is required", name)
	}
	if trimmed == "." || trimmed == ".." {
		return fmt.Errorf("invalid %s", name)
	}
	for i := 0; i < len(value); i++ {
		if value[i] < 0x20 || value[i] == 0x7F {
			return fmt.Errorf("invalid %s", name)
		}
	}
	return nil
}
