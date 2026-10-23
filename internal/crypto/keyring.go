package crypto

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
)

// Keyring holds the key-encryption keys. New data is always wrapped with the
// primary key; the others are kept so that older revisions can still be read
// until "syncd keys rewrap" moves them to the primary key.
//
// File format, one key per line, '#' starts a comment:
//
//	<id> <base64 of 32 random bytes>
type Keyring struct {
	primary string
	keys    map[string][]byte
}

var keyIDRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

func LoadKeyringFile(path, primary string) (*Keyring, error) {
	f, err := os.Open(path) //nolint:gosec // the path is operator configuration
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck // read-only

	if err := checkPermissions(f); err != nil {
		return nil, err
	}
	return ParseKeyring(f, primary)
}

func ParseKeyring(r io.Reader, primary string) (*Keyring, error) {
	k := &Keyring{primary: primary, keys: map[string][]byte{}}
	sc := bufio.NewScanner(r)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 || !keyIDRe.MatchString(fields[0]) {
			return nil, fmt.Errorf("keyring line %d: expected \"<id> <base64 key>\"", n)
		}
		key, err := base64.StdEncoding.DecodeString(fields[1])
		if err != nil || len(key) != keySize {
			return nil, fmt.Errorf("keyring line %d: key %q must be %d bytes of base64", n, fields[0], keySize)
		}
		if _, dup := k.keys[fields[0]]; dup {
			return nil, fmt.Errorf("keyring line %d: duplicate key id %q", n, fields[0])
		}
		if bytes.Count(key, []byte{0}) == keySize {
			return nil, fmt.Errorf("keyring line %d: key %q is all zeros", n, fields[0])
		}
		k.keys[fields[0]] = key
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if _, ok := k.keys[primary]; !ok {
		return nil, fmt.Errorf("keyring: primary key %q not found", primary)
	}
	return k, nil
}

func (k *Keyring) PrimaryID() string { return k.primary }

func (k *Keyring) primaryKey() (string, []byte) { return k.primary, k.keys[k.primary] }

// GenerateKeyLine returns a new keyring line for the given id.
func GenerateKeyLine(id string) (string, error) {
	if !keyIDRe.MatchString(id) {
		return "", fmt.Errorf("key id must match %s", keyIDRe)
	}
	key := make([]byte, keySize)
	if _, err := rand.Read(key); err != nil {
		return "", err
	}
	return id + " " + base64.StdEncoding.EncodeToString(key), nil
}
