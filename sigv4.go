package nitrokit

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"maps"
	"net/http"
	"slices"
	"strings"
	"time"
)

// signV4 signs an AWS API request with Signature Version 4. It exists so
// the Route 53 solver needs no AWS SDK: the module talks to exactly two
// Route 53 operations, and signing them is a fixed HMAC-SHA256 chain over
// a canonical form of the request. A signing bug fails closed — AWS
// rejects the request — so the risk of owning this code is an outage
// alarm, not a silent hole.
//
// It signs the host header, content-type if set, and every x-amz-*
// header already set on the request. Call it after all headers are final.
func signV4(req *http.Request, body []byte, accessKey, secretKey, sessionToken, region, service string, now time.Time) {
	if sessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", sessionToken)
	}
	amzDate := now.UTC().Format("20060102T150405Z")
	date := amzDate[:8]
	req.Header.Set("X-Amz-Date", amzDate)

	// Canonical headers: lowercase name, trimmed value, sorted by name.
	headers := map[string]string{"host": req.Host}
	if req.Host == "" {
		headers["host"] = req.URL.Host
	}
	for name, vals := range req.Header {
		lower := strings.ToLower(name)
		if lower == "content-type" || strings.HasPrefix(lower, "x-amz-") {
			headers[lower] = strings.TrimSpace(vals[0])
		}
	}
	names := slices.Sorted(maps.Keys(headers))
	var canonHeaders strings.Builder
	for _, n := range names {
		canonHeaders.WriteString(n + ":" + headers[n] + "\n")
	}
	signedHeaders := strings.Join(names, ";")

	payloadHash := sha256.Sum256(body)
	canonical := strings.Join([]string{
		req.Method,
		canonicalURI(req),
		canonicalQuery(req),
		canonHeaders.String(),
		signedHeaders,
		hex.EncodeToString(payloadHash[:]),
	}, "\n")
	canonicalHash := sha256.Sum256([]byte(canonical))

	scope := date + "/" + region + "/" + service + "/aws4_request"
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		scope,
		hex.EncodeToString(canonicalHash[:]),
	}, "\n")

	key := hmacSHA256([]byte("AWS4"+secretKey), date)
	key = hmacSHA256(key, region)
	key = hmacSHA256(key, service)
	key = hmacSHA256(key, "aws4_request")
	signature := hex.EncodeToString(hmacSHA256(key, stringToSign))

	req.Header.Set("Authorization",
		"AWS4-HMAC-SHA256 Credential="+accessKey+"/"+scope+
			", SignedHeaders="+signedHeaders+
			", Signature="+signature)
}

func hmacSHA256(key []byte, msg string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(msg))
	return m.Sum(nil)
}

func canonicalURI(req *http.Request) string {
	if req.URL.Path == "" {
		return "/"
	}
	// The paths this module signs are plain ASCII API paths; EscapedPath
	// re-encodes anything that is not.
	return req.URL.EscapedPath()
}

// canonicalQuery is the query parameters sorted by name and re-encoded
// per RFC 3986 (AWS rejects '+' for space, which url.Values.Encode emits).
func canonicalQuery(req *http.Request) string {
	q := req.URL.Query()
	names := slices.Sorted(maps.Keys(q))
	var parts []string
	for _, n := range names {
		vals := slices.Clone(q[n])
		slices.Sort(vals)
		for _, v := range vals {
			parts = append(parts, awsEscape(n)+"="+awsEscape(v))
		}
	}
	return strings.Join(parts, "&")
}

// awsEscape percent-encodes everything outside the RFC 3986 unreserved
// set.
func awsEscape(s string) string {
	const unreserved = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
	var b strings.Builder
	for i := range len(s) {
		c := s[i]
		if strings.IndexByte(unreserved, c) >= 0 {
			b.WriteByte(c)
		} else {
			b.WriteString("%" + strings.ToUpper(hex.EncodeToString([]byte{c})))
		}
	}
	return b.String()
}
