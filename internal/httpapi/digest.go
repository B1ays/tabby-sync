package httpapi

import (
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"hash"
	"net/http"
	"strings"
)

// reprDigest formats a Repr-Digest / Content-Digest value (RFC 9530).
func reprDigest(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha-256=:" + base64.StdEncoding.EncodeToString(sum[:]) + ":"
}

var digestAlgs = map[string]func() hash.Hash{"sha-256": sha256.New, "sha-512": sha512.New}

// checkRequestDigest verifies Content-Digest and Repr-Digest request
// headers against the body (identical here, as content codings are
// refused). Unknown algorithms are ignored as RFC 9530 allows; a malformed
// value or a mismatch for a known one is an error.
func checkRequestDigest(r *http.Request, body []byte) error {
	for _, name := range []string{"Content-Digest", "Repr-Digest"} {
		for _, v := range r.Header.Values(name) {
			for _, member := range strings.Split(v, ",") {
				alg, val, ok := strings.Cut(strings.TrimSpace(member), "=")
				newHash, known := digestAlgs[strings.ToLower(alg)]
				if !known {
					continue
				}
				if !ok || len(val) < 2 || val[0] != ':' || val[len(val)-1] != ':' {
					return &bodyError{http.StatusBadRequest, name + " is malformed."}
				}
				want, err := base64.StdEncoding.DecodeString(val[1 : len(val)-1])
				if err != nil {
					return &bodyError{http.StatusBadRequest, name + " is malformed."}
				}
				h := newHash()
				h.Write(body)
				if subtle.ConstantTimeCompare(h.Sum(nil), want) != 1 {
					return &bodyError{http.StatusBadRequest, name + " does not match the request body."}
				}
			}
		}
	}
	return nil
}
