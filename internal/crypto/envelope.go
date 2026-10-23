// Package crypto implements envelope encryption of config revisions.
//
// Each revision is sealed with its own random 256-bit data key (DEK) using
// AES-256-GCM. The DEK is in turn sealed with a key-encryption key (KEK) from
// the keyring. Both layers bind the ciphertext to its owner, config and
// revision through additional authenticated data, so a row copied to another
// user, config or revision in the database fails to decrypt instead of
// silently showing up there.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
)

const formatV1 byte = 1

const (
	keySize   = 32
	nonceSize = 12
)

var ErrDecrypt = errors.New("crypto: message authentication failed")

// Binding identifies where a ciphertext belongs.
type Binding struct {
	UserID   int64
	ConfigID int64
	Revision int32
}

func (b Binding) bytes(label string, kekID string) []byte {
	out := make([]byte, 0, len(label)+1+len(kekID)+1+20)
	out = append(out, label...)
	out = append(out, 0)
	out = append(out, kekID...)
	out = append(out, 0)
	out = binary.BigEndian.AppendUint64(out, uint64(b.UserID))
	out = binary.BigEndian.AppendUint64(out, uint64(b.ConfigID))
	out = binary.BigEndian.AppendUint32(out, uint32(b.Revision))
	return out
}

// Sealed is what gets stored in the database.
type Sealed struct {
	Ciphertext []byte // format byte || nonce || AES-GCM(DEK, plaintext)
	WrappedDEK []byte // format byte || nonce || AES-GCM(KEK, DEK)
	KEKID      string
}

func (k *Keyring) Seal(plaintext []byte, b Binding) (Sealed, error) {
	dek := make([]byte, keySize)
	defer clear(dek)
	if _, err := rand.Read(dek); err != nil {
		return Sealed{}, err
	}
	ct, err := seal(dek, plaintext, b.bytes("tabby-sync/content/v1", ""))
	if err != nil {
		return Sealed{}, err
	}
	id, kek := k.primaryKey()
	wrapped, err := seal(kek, dek, b.bytes("tabby-sync/dek/v1", id))
	if err != nil {
		return Sealed{}, err
	}
	return Sealed{Ciphertext: ct, WrappedDEK: wrapped, KEKID: id}, nil
}

func (k *Keyring) Open(s Sealed, b Binding) ([]byte, error) {
	dek, err := k.unwrap(s, b)
	if err != nil {
		return nil, err
	}
	defer clear(dek)
	return open(dek, s.Ciphertext, b.bytes("tabby-sync/content/v1", ""))
}

// Rewrap re-seals the DEK under the primary KEK. The content ciphertext is
// left untouched. It reports false if the DEK is already under the primary KEK.
func (k *Keyring) Rewrap(s Sealed, b Binding) (Sealed, bool, error) {
	id, kek := k.primaryKey()
	if s.KEKID == id {
		return s, false, nil
	}
	dek, err := k.unwrap(s, b)
	if err != nil {
		return s, false, err
	}
	defer clear(dek)
	wrapped, err := seal(kek, dek, b.bytes("tabby-sync/dek/v1", id))
	if err != nil {
		return s, false, err
	}
	return Sealed{Ciphertext: s.Ciphertext, WrappedDEK: wrapped, KEKID: id}, true, nil
}

func (k *Keyring) unwrap(s Sealed, b Binding) ([]byte, error) {
	kek, ok := k.keys[s.KEKID]
	if !ok {
		return nil, fmt.Errorf("crypto: unknown KEK %q", s.KEKID)
	}
	dek, err := open(kek, s.WrappedDEK, b.bytes("tabby-sync/dek/v1", s.KEKID))
	if err != nil {
		return nil, err
	}
	if len(dek) != keySize {
		clear(dek)
		return nil, ErrDecrypt
	}
	return dek, nil
}

func seal(key, plaintext, aad []byte) ([]byte, error) {
	aead, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 1+nonceSize, 1+nonceSize+len(plaintext)+aead.Overhead())
	out[0] = formatV1
	if _, err := rand.Read(out[1:]); err != nil {
		return nil, err
	}
	return aead.Seal(out, out[1:], plaintext, aad), nil
}

func open(key, msg, aad []byte) ([]byte, error) {
	if len(msg) < 1+nonceSize || msg[0] != formatV1 {
		return nil, ErrDecrypt
	}
	aead, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	pt, err := aead.Open(nil, msg[1:1+nonceSize], msg[1+nonceSize:], aad)
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
