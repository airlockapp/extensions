// Package canonical provides RFC 8785 JSON Canonicalization Scheme (JCS).
package canonical

import (
	"encoding/json"
	"fmt"
)

// Canonicalize converts an object to a JCS canonical JSON string.
// It marshals to JSON, then unmarshals to a generic structure (which sorts map keys),
// strips nulls, and re-marshals to produce sorted, compact JSON.
func Canonicalize(v interface{}) (string, error) {
	// First marshal the struct to JSON
	b, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("canonical: marshal: %w", err)
	}

	// Unmarshal into generic structure so map keys are sorted on re-marshal
	var generic interface{}
	if err := json.Unmarshal(b, &generic); err != nil {
		return "", fmt.Errorf("canonical: unmarshal: %w", err)
	}

	// Strip nulls and re-marshal (Go's json.Marshal sorts map keys)
	stripped := stripNulls(generic)
	out, err := json.Marshal(stripped)
	if err != nil {
		return "", fmt.Errorf("canonical: re-marshal: %w", err)
	}

	return string(out), nil
}

// CanonicalizeBytes is like Canonicalize but returns UTF-8 bytes.
func CanonicalizeBytes(v interface{}) ([]byte, error) {
	s, err := Canonicalize(v)
	if err != nil {
		return nil, err
	}
	return []byte(s), nil
}

// stripNulls recursively removes null values from maps.
func stripNulls(v interface{}) interface{} {
	switch val := v.(type) {
	case map[string]interface{}:
		result := make(map[string]interface{})
		for k, v := range val {
			if v != nil {
				result[k] = stripNulls(v)
			}
		}
		return result
	case []interface{}:
		result := make([]interface{}, len(val))
		for i, item := range val {
			result[i] = stripNulls(item)
		}
		return result
	default:
		return v
	}
}
