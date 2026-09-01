package nitrokit_test

import (
	"bytes"
	"mime/multipart"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hammondus/nitrokit"
)

func TestReadFormURLEncoded(t *testing.T) {
	req := httptest.NewRequest("POST", "/", strings.NewReader("name=x&msg=hello"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	if !nitrokit.ReadForm(rec, req, 1<<10) {
		t.Fatalf("valid form rejected: %s", rec.Body)
	}
	if got := req.PostFormValue("msg"); got != "hello" {
		t.Errorf("msg = %q, want hello", got)
	}
}

// TestReadFormMultipart pins the reason the Content-Type dispatch exists:
// r.ParseForm silently ignores a multipart body, so a helper that only
// called it would report every field empty.
func TestReadFormMultipart(t *testing.T) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	mw.WriteField("msg", "hello")
	fw, _ := mw.CreateFormFile("upload", "a.txt")
	fw.Write([]byte("file bytes"))
	mw.Close()

	req := httptest.NewRequest("POST", "/", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rec := httptest.NewRecorder()
	if !nitrokit.ReadForm(rec, req, 1<<20) {
		t.Fatalf("valid multipart form rejected: %s", rec.Body)
	}
	if got := req.PostFormValue("msg"); got != "hello" {
		t.Errorf("msg = %q, want hello", got)
	}
	if req.MultipartForm == nil || len(req.MultipartForm.File["upload"]) != 1 {
		t.Error("file part missing")
	}
}

func TestReadFormTooLarge(t *testing.T) {
	req := httptest.NewRequest("POST", "/", strings.NewReader("msg="+strings.Repeat("a", 100)))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	if nitrokit.ReadForm(rec, req, 10) {
		t.Fatal("oversize body accepted")
	}
	if rec.Code != 413 {
		t.Errorf("status = %d, want 413", rec.Code)
	}
}

func TestReadFormBadMultipart(t *testing.T) {
	req := httptest.NewRequest("POST", "/", strings.NewReader("not multipart"))
	req.Header.Set("Content-Type", "multipart/form-data") // no boundary
	rec := httptest.NewRecorder()
	if nitrokit.ReadForm(rec, req, 1<<10) {
		t.Fatal("boundary-less multipart accepted")
	}
	if rec.Code != 400 {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}
