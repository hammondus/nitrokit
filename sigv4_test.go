// Internal tests: the signer is unexported.
package nitrokit

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestSignV4DocVector pins the signer to the worked example in AWS's
// Signature Version 4 documentation (GET iam ListUsers, 2015-08-30). The
// expected signature was reproduced independently with a Python
// implementation before being written here, so this is not the Go code
// checking itself.
func TestSignV4DocVector(t *testing.T) {
	req, err := http.NewRequest("GET", "https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")

	now := time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC)
	signV4(req, nil,
		"AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "",
		"us-east-1", "iam", now)

	auth := req.Header.Get("Authorization")
	want := "AWS4-HMAC-SHA256 " +
		"Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, " +
		"SignedHeaders=content-type;host;x-amz-date, " +
		"Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
	if auth != want {
		t.Errorf("Authorization =\n%s\nwant\n%s", auth, want)
	}
	if got := req.Header.Get("X-Amz-Date"); got != "20150830T123600Z" {
		t.Errorf("X-Amz-Date = %q", got)
	}
}

// TestSignV4SessionToken checks a temporary-credential token is both sent
// and signed, so STS credentials work.
func TestSignV4SessionToken(t *testing.T) {
	req, err := http.NewRequest("POST", "https://route53.amazonaws.com/2013-04-01/hostedzone/Z1/rrset/", strings.NewReader("body"))
	if err != nil {
		t.Fatal(err)
	}
	signV4(req, []byte("body"), "AKID", "secret", "the-token", "us-east-1", "route53", time.Now())

	if got := req.Header.Get("X-Amz-Security-Token"); got != "the-token" {
		t.Errorf("X-Amz-Security-Token = %q", got)
	}
	if auth := req.Header.Get("Authorization"); !strings.Contains(auth, "x-amz-security-token") {
		t.Errorf("token not in SignedHeaders: %s", auth)
	}
}

func TestAWSEscape(t *testing.T) {
	tests := []struct{ in, want string }{
		{"abc-._~123", "abc-._~123"},
		{"a b", "a%20b"},
		{"a+b/c", "a%2Bb%2Fc"},
		{"*", "%2A"},
	}
	for _, tt := range tests {
		if got := awsEscape(tt.in); got != tt.want {
			t.Errorf("awsEscape(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
