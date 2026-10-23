package httpapi

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"

	"tabbysync/internal/configs"
)

// problem is an RFC 9457 error body. "detail" is also what Django REST
// Framework clients look for.
type problem struct {
	Title     string            `json:"title"`
	Status    int               `json:"status"`
	Detail    string            `json:"detail,omitempty"`
	Errors    map[string]string `json:"errors,omitempty"`
	RequestID string            `json:"request_id,omitempty"`
}

func writeProblem(w http.ResponseWriter, r *http.Request, status int, detail string) {
	writeProblemBody(w, r, problem{Status: status, Detail: detail})
}

func writeProblemBody(w http.ResponseWriter, r *http.Request, p problem) {
	if p.Title == "" {
		p.Title = http.StatusText(p.Status)
	}
	p.RequestID = requestIDFrom(r.Context())
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(p.Status)
	_ = json.NewEncoder(w).Encode(p)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeError maps domain errors to responses. Anything unexpected is logged
// with the request ID and returned as a bare 500.
func (s *Server) writeError(w http.ResponseWriter, r *http.Request, err error) {
	var verr *configs.ValidationError
	var perr *configs.PreconditionError
	var berr *bodyError
	switch {
	case errors.As(err, &berr):
		writeProblem(w, r, berr.status, berr.msg)
	case errors.As(err, &verr):
		writeProblemBody(w, r, problem{
			Status: http.StatusBadRequest,
			Detail: verr.Error(),
			Errors: map[string]string{verr.Field: verr.Reason},
		})
	case errors.As(err, &perr):
		w.Header().Set("ETag", etag(perr.Current))
		writeProblem(w, r, http.StatusPreconditionFailed, perr.Error())
	case errors.Is(err, configs.ErrNotFound):
		writeProblem(w, r, http.StatusNotFound, "Not found.")
	case errors.Is(err, configs.ErrTooManyConfig):
		writeProblem(w, r, http.StatusConflict, "Config limit reached.")
	default:
		s.log.ErrorContext(r.Context(), "request failed", "err", err)
		writeProblem(w, r, http.StatusInternalServerError, "")
	}
}

func etag(version int64) string { return `"v` + strconv.FormatInt(version, 10) + `"` }

func logLevelFor(status int) slog.Level {
	switch {
	case status >= 500:
		return slog.LevelError
	case status >= 400:
		return slog.LevelWarn
	}
	return slog.LevelInfo
}
