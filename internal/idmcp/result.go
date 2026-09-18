package idmcp

import (
	"encoding/json"
	"fmt"
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
	if value == "" {
		return fmt.Errorf("%s is required", name)
	}
	return nil
}
