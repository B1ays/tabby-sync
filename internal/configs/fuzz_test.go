package configs

import "testing"

func FuzzValidateContent(f *testing.F) {
	for _, s := range []string{"{}", "a: 1", "[1]", "a: &x 1\nb: *x", "\xff", "a: !!binary aGVsbG8="} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		_ = validateContent(s, 1<<16) // must not panic or hang
	})
}
