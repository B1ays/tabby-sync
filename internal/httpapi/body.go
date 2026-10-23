package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
)

type bodyError struct {
	status int
	msg    string
}

func (e *bodyError) Error() string { return e.msg }

// decodeJSON reads exactly one JSON object of at most limit bytes. Unknown
// fields are rejected so that typos and unsupported fields fail loudly
// instead of being silently ignored.
func decodeJSON(w http.ResponseWriter, r *http.Request, limit int64, dst any) error {
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mt != "application/json" {
		return &bodyError{http.StatusUnsupportedMediaType, "Content-Type must be application/json."}
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, limit))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return &bodyError{http.StatusRequestEntityTooLarge, fmt.Sprintf("Request body exceeds %d bytes.", limit)}
		}
		var ute *json.UnmarshalTypeError
		if errors.As(err, &ute) {
			return &bodyError{http.StatusBadRequest, fmt.Sprintf("Field %q has the wrong type.", ute.Field)}
		}
		if msg := err.Error(); strings.HasPrefix(msg, "json: unknown field ") {
			return &bodyError{http.StatusBadRequest, "Unknown field " + strings.TrimPrefix(msg, "json: unknown field ") + "."}
		}
		var ne *nullError
		if errors.As(err, &ne) {
			return &bodyError{http.StatusBadRequest, "Field may not be null."}
		}
		return &bodyError{http.StatusBadRequest, "Malformed JSON body."}
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return &bodyError{http.StatusBadRequest, "Body must contain a single JSON object."}
	}
	return nil
}

type nullError struct{}

func (*nullError) Error() string { return "null not allowed" }

// optString is a JSON field that may be absent but not null.
type optString struct {
	Set   bool
	Value string
}

func (o *optString) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, []byte("null")) {
		return &nullError{}
	}
	o.Set = true
	return json.Unmarshal(b, &o.Value)
}

// optNullString is a JSON field that may be absent, null or a string.
type optNullString struct {
	Set   bool
	Value *string
}

func (o *optNullString) UnmarshalJSON(b []byte) error {
	o.Set = true
	return json.Unmarshal(b, &o.Value)
}

// optNullInt is a JSON field that may be absent, null or an integer.
type optNullInt struct {
	Set   bool
	Value *int64
}

func (o *optNullInt) UnmarshalJSON(b []byte) error {
	o.Set = true
	return json.Unmarshal(b, &o.Value)
}
