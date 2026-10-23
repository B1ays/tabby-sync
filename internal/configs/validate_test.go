package configs

import (
	"strings"
	"testing"
	"time"
)

func TestValidateContent(t *testing.T) {
	ok := []string{
		"{}",
		`{"hotkeys": {}, "profiles": []}`,
		"version: 3\nprofiles:\n  - name: srv\n    type: ssh\n",
		"encrypted: true\nstore: abc\n",
	}
	for _, s := range ok {
		if err := validateContent(s, 1<<20); err != nil {
			t.Errorf("%q: %v", s, err)
		}
	}
	bad := []string{
		"",
		"   ",
		"[1, 2]",
		"just a string",
		"a: [unclosed",
		"a: 1\n---\nb: 2\n",
		"a: 1\x00",
		"a: \xff\xfe",
		"a: " + strings.Repeat("x", 100),
	}
	for _, s := range bad {
		if err := validateContent(s, 64); err == nil {
			t.Errorf("%q accepted", s)
		}
	}
}

func TestValidateContentAliasBomb(t *testing.T) {
	// "Billion laughs": the YAML library must refuse to expand this.
	bomb := `a: &a ["x","x","x","x","x","x","x","x","x"]
b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]
c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]
d: &d [*c,*c,*c,*c,*c,*c,*c,*c,*c]
e: &e [*d,*d,*d,*d,*d,*d,*d,*d,*d]
f: &f [*e,*e,*e,*e,*e,*e,*e,*e,*e]
g: &g [*f,*f,*f,*f,*f,*f,*f,*f,*f]
h: &h [*g,*g,*g,*g,*g,*g,*g,*g,*g]
i: &i [*h,*h,*h,*h,*h,*h,*h,*h,*h]
`
	// Decoding into a yaml.Node does not expand aliases, so this is cheap;
	// the test guards against switching to a decoder that does.
	start := time.Now()
	_ = validateContent(bomb, 1<<20)
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("validation took %v", d)
	}
}

func TestValidateName(t *testing.T) {
	for _, s := range []string{"Work", "Конфиг 1", strings.Repeat("я", 255)} {
		if err := validateName(s); err != nil {
			t.Errorf("%q: %v", s, err)
		}
	}
	for _, s := range []string{"", strings.Repeat("a", 256), "a\nb", "a\x1b[31m"} {
		if err := validateName(s); err == nil {
			t.Errorf("%q accepted", s)
		}
	}
}

func TestValidateAppVersion(t *testing.T) {
	if err := validateAppVersion("1.0.230"); err != nil {
		t.Error(err)
	}
	for _, s := range []string{strings.Repeat("1", 33), "1.0\n", "версия"} {
		if err := validateAppVersion(s); err == nil {
			t.Errorf("%q accepted", s)
		}
	}
}
