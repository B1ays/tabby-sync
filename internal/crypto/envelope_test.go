package crypto

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func testKeyring(t *testing.T, primary string, ids ...string) *Keyring {
	t.Helper()
	var sb strings.Builder
	sb.WriteString("# test keyring\n\n")
	for _, id := range ids {
		line, err := GenerateKeyLine(id)
		if err != nil {
			t.Fatal(err)
		}
		sb.WriteString(line + "  # comment\n")
	}
	k, err := ParseKeyring(strings.NewReader(sb.String()), primary)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestSealOpenRoundTrip(t *testing.T) {
	k := testKeyring(t, "a", "a")
	b := Binding{UserID: 1, ConfigID: 2, Revision: 3}
	pt := []byte("hotkeys: {}\nprofiles: []\n")
	s, err := k.Seal(pt, b)
	if err != nil {
		t.Fatal(err)
	}
	if s.KEKID != "a" {
		t.Fatalf("KEKID = %q", s.KEKID)
	}
	if bytes.Contains(s.Ciphertext, pt) {
		t.Fatal("plaintext visible in ciphertext")
	}
	got, err := k.Open(s, b)
	if err != nil || !bytes.Equal(got, pt) {
		t.Fatalf("Open = %q, %v", got, err)
	}

	s2, _ := k.Seal(pt, b)
	if bytes.Equal(s.Ciphertext, s2.Ciphertext) || bytes.Equal(s.WrappedDEK, s2.WrappedDEK) {
		t.Fatal("sealing twice gave identical output")
	}
}

func TestBindingIsEnforced(t *testing.T) {
	k := testKeyring(t, "a", "a")
	b := Binding{UserID: 1, ConfigID: 2, Revision: 3}
	s, err := k.Seal([]byte("x: 1"), b)
	if err != nil {
		t.Fatal(err)
	}
	for _, other := range []Binding{
		{UserID: 9, ConfigID: 2, Revision: 3},
		{UserID: 1, ConfigID: 9, Revision: 3},
		{UserID: 1, ConfigID: 2, Revision: 9},
	} {
		if _, err := k.Open(s, other); !errors.Is(err, ErrDecrypt) {
			t.Errorf("Open with %+v: err = %v, want ErrDecrypt", other, err)
		}
	}
}

func TestTamperingDetected(t *testing.T) {
	k := testKeyring(t, "a", "a")
	b := Binding{UserID: 1, ConfigID: 1, Revision: 1}
	s, _ := k.Seal([]byte("x: 1"), b)

	for name, mutate := range map[string]func(*Sealed){
		"ciphertext": func(s *Sealed) { s.Ciphertext[len(s.Ciphertext)-1] ^= 1 },
		"nonce":      func(s *Sealed) { s.Ciphertext[1] ^= 1 },
		"format":     func(s *Sealed) { s.Ciphertext[0] = 2 },
		"wrapped":    func(s *Sealed) { s.WrappedDEK[len(s.WrappedDEK)-1] ^= 1 },
		"truncated":  func(s *Sealed) { s.Ciphertext = s.Ciphertext[:5] },
	} {
		c := Sealed{
			Ciphertext: bytes.Clone(s.Ciphertext),
			WrappedDEK: bytes.Clone(s.WrappedDEK),
			KEKID:      s.KEKID,
		}
		mutate(&c)
		if _, err := k.Open(c, b); !errors.Is(err, ErrDecrypt) {
			t.Errorf("%s: err = %v, want ErrDecrypt", name, err)
		}
	}
}

func TestCiphertextSwapBetweenRevisionsFails(t *testing.T) {
	k := testKeyring(t, "a", "a")
	s1, _ := k.Seal([]byte("v: 1"), Binding{UserID: 1, ConfigID: 1, Revision: 1})
	s2, _ := k.Seal([]byte("v: 2"), Binding{UserID: 1, ConfigID: 1, Revision: 2})
	// Content of revision 1 with the data key of revision 2.
	mixed := Sealed{Ciphertext: s1.Ciphertext, WrappedDEK: s2.WrappedDEK, KEKID: "a"}
	if _, err := k.Open(mixed, Binding{UserID: 1, ConfigID: 1, Revision: 2}); err == nil {
		t.Fatal("mixed revision opened")
	}
}

func TestRewrap(t *testing.T) {
	var lines []string
	for _, id := range []string{"old", "new"} {
		l, _ := GenerateKeyLine(id)
		lines = append(lines, l)
	}
	both := strings.Join(lines, "\n")
	oldK, err := ParseKeyring(strings.NewReader(both), "old")
	if err != nil {
		t.Fatal(err)
	}
	newK, _ := ParseKeyring(strings.NewReader(both), "new")
	onlyNew, _ := ParseKeyring(strings.NewReader(lines[1]), "new")

	b := Binding{UserID: 5, ConfigID: 6, Revision: 7}
	s, _ := oldK.Seal([]byte("a: b"), b)
	if _, err := onlyNew.Open(s, b); err == nil {
		t.Fatal("opened without the old key")
	}

	r, changed, err := newK.Rewrap(s, b)
	if err != nil || !changed || r.KEKID != "new" || !bytes.Equal(r.Ciphertext, s.Ciphertext) {
		t.Fatalf("Rewrap = %+v, %v, %v", r, changed, err)
	}
	if got, err := onlyNew.Open(r, b); err != nil || string(got) != "a: b" {
		t.Fatalf("Open after rewrap = %q, %v", got, err)
	}
	if _, changed, _ := newK.Rewrap(r, b); changed {
		t.Fatal("second rewrap reported a change")
	}
}

func TestParseKeyringErrors(t *testing.T) {
	good, _ := GenerateKeyLine("k1")
	for name, in := range map[string]string{
		"missing primary": good,
		"bad base64":      "p not-base64!!",
		"short key":       "p AAAA",
		"zero key":        "p AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		"bad id":          "p/x " + strings.Fields(good)[1],
		"duplicate":       strings.Replace(good, "k1", "p", 1) + "\n" + strings.Replace(good, "k1", "p", 1),
		"extra field":     strings.Replace(good, "k1", "p", 1) + " extra",
	} {
		if _, err := ParseKeyring(strings.NewReader(in), "p"); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}
