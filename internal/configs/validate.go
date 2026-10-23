package configs

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"

	"go.yaml.in/yaml/v3"
)

// ValidationError is a client error tied to one field.
type ValidationError struct {
	Field  string
	Reason string
}

func (e *ValidationError) Error() string { return e.Field + ": " + e.Reason }

func invalid(field, format string, args ...any) error {
	return &ValidationError{Field: field, Reason: fmt.Sprintf(format, args...)}
}

// validateContent accepts what Tabby can load: a UTF-8 YAML (or JSON, which
// is YAML) document whose top level is a mapping. The desktop client parses
// the stored content and indexes into it, so anything else would break every
// device synced to the config.
func validateContent(s string, maxBytes int) error {
	if len(s) > maxBytes {
		return invalid("content", "exceeds %d bytes", maxBytes)
	}
	if !utf8.ValidString(s) {
		return invalid("content", "is not valid UTF-8")
	}
	if strings.IndexByte(s, 0) >= 0 {
		return invalid("content", "contains a NUL byte")
	}
	dec := yaml.NewDecoder(bytes.NewReader([]byte(s)))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		return invalid("content", "is not valid YAML or JSON")
	}
	if len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return invalid("content", "must be a mapping at the top level")
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return invalid("content", "must be a single document")
	}
	return nil
}

func validateName(s string) error {
	if s == "" || utf8.RuneCountInString(s) > 255 {
		return invalid("name", "must be 1 to 255 characters")
	}
	if !utf8.ValidString(s) || strings.IndexFunc(s, unicode.IsControl) >= 0 {
		return invalid("name", "contains invalid characters")
	}
	return nil
}

func validateAppVersion(s string) error {
	if len(s) > 32 {
		return invalid("last_used_with_version", "must be at most 32 characters")
	}
	for _, r := range s {
		if r < 0x20 || r > 0x7e {
			return invalid("last_used_with_version", "must be printable ASCII")
		}
	}
	return nil
}
