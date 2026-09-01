package nitrokit

import (
	"errors"
	"mime"
	"net/http"
)

// maxMultipartMemory is the in-memory threshold for multipart parsing;
// file parts beyond it spill to temp files. A constant, not a parameter:
// it tunes memory use, not the request cap, and 10 MiB keeps a
// concurrent-upload burst from multiplying into real memory pressure.
const maxMultipartMemory = 10 << 20

// ReadForm parses a form request body of at most maxBytes, handling both
// encodings a browser form can send. On failure it writes the error
// response itself — 413 for an oversize body, 400 otherwise — and
// returns false; the caller returns without writing anything. On success
// the values are in r.Form / r.PostForm (and r.MultipartForm for file
// uploads) as usual.
//
// The cap is per endpoint, like ReadJSON's: a contact form is a few KiB,
// an upload form is whatever its files justify.
//
// The multipart branch exists because r.ParseForm silently ignores a
// multipart body — a handler that "parses the form" and finds every
// field empty is the classic symptom. Dispatching on the Content-Type
// here means a form that later grows a file input keeps working.
func ReadForm(w http.ResponseWriter, r *http.Request, maxBytes int64) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	ct, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	var err error
	if ct == "multipart/form-data" {
		err = r.ParseMultipartForm(min(maxBytes, maxMultipartMemory))
	} else {
		err = r.ParseForm()
	}
	if err == nil {
		return true
	}
	if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
		http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
	} else {
		http.Error(w, "bad form", http.StatusBadRequest)
	}
	return false
}
