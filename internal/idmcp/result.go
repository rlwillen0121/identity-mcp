package idmcp

import (
	"encoding/json"
	"fmt"
	"net/url"
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

func hasDotSegment(s string) bool {
	norm := strings.ReplaceAll(s, `\`, "/")
	for _, seg := range strings.Split(norm, "/") {
		seg = strings.TrimSpace(seg)
		if seg == "." || seg == ".." ||
			strings.EqualFold(seg, "%2e") ||
			strings.EqualFold(seg, "%2e%2e") ||
			strings.EqualFold(seg, ".%2e") ||
			strings.EqualFold(seg, "%2e.") {
			return true
		}
	}
	return false
}

func Require(name, value string) error {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return fmt.Errorf("%s is required", name)
	}
	for i := 0; i < len(value); i++ {
		if value[i] < 0x20 || value[i] == 0x7F {
			return fmt.Errorf("invalid %s", name)
		}
	}
	if hasDotSegment(trimmed) {
		return fmt.Errorf("invalid %s", name)
	}
	if strings.Contains(trimmed, "%") {
		if unescaped, err := url.PathUnescape(trimmed); err == nil && hasDotSegment(unescaped) {
			return fmt.Errorf("invalid %s", name)
		}
	}
	return nil
}

