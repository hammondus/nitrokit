package nitrokit

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// DNSSolver places and removes the TXT records that prove domain control
// for an ACME DNS-01 challenge. SetTXT must not return until the record
// is visible to the certificate authority's resolvers — propagation is
// provider-specific, so waiting for it is the solver's job, bounded by
// ctx. Implement this interface in a consuming project to support a DNS
// provider nitrokit does not ship a solver for.
type DNSSolver interface {
	// SetTXT creates or replaces the TXT record at fqdn (for example
	// "_acme-challenge.example.com") with the given value.
	SetTXT(ctx context.Context, fqdn, value string) error

	// CleanupTXT removes the record SetTXT created.
	CleanupTXT(ctx context.Context, fqdn, value string) error
}

// Route53 is a DNSSolver for an Amazon Route 53 hosted zone. It talks to
// the two operations it needs directly — ChangeResourceRecordSets and
// GetChange — signed with an in-module SigV4 implementation, so it needs
// no AWS SDK.
//
// Scope the credentials to the blast radius of a leaked key on a web
// host: an IAM policy allowing route53:ChangeResourceRecordSets on this
// one hosted zone plus route53:GetChange, and nothing else.
type Route53 struct {
	zoneID       string
	accessKey    string
	secretKey    string
	sessionToken string
	endpoint     string // overridden in tests
	client       *http.Client
}

// NewRoute53 returns a solver for the given hosted zone ID (the
// "Z0123456789ABC" value, not the domain). Credentials come from the
// standard AWS environment: AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY,
// plus AWS_SESSION_TOKEN when present for temporary credentials. Missing
// credentials are an error here, at startup, not at first renewal months
// later.
func NewRoute53(zoneID string) (*Route53, error) {
	if zoneID == "" {
		return nil, errors.New("nitrokit: Route 53 hosted zone ID is empty")
	}
	access := os.Getenv("AWS_ACCESS_KEY_ID")
	secret := os.Getenv("AWS_SECRET_ACCESS_KEY")
	if access == "" || secret == "" {
		return nil, errors.New("nitrokit: AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY must be set for the Route 53 solver")
	}
	return &Route53{
		zoneID:       zoneID,
		accessKey:    access,
		secretKey:    secret,
		sessionToken: os.Getenv("AWS_SESSION_TOKEN"),
		endpoint:     "https://route53.amazonaws.com",
		client:       &http.Client{Timeout: 30 * time.Second},
	}, nil
}

// route53TTL is deliberately short: challenge records live for one
// validation and should not linger in caches.
const route53TTL = 30

// route53PollInterval paces the GetChange polling. A variable only so
// tests need not wait real seconds.
var route53PollInterval = 5 * time.Second

// XML shapes for the two Route 53 operations.
type route53Change struct {
	XMLName xml.Name        `xml:"ChangeResourceRecordSetsRequest"`
	Xmlns   string          `xml:"xmlns,attr"`
	Changes []route53Record `xml:"ChangeBatch>Changes>Change"`
}

type route53Record struct {
	Action string `xml:"Action"`
	Name   string `xml:"ResourceRecordSet>Name"`
	Type   string `xml:"ResourceRecordSet>Type"`
	TTL    int    `xml:"ResourceRecordSet>TTL"`
	Value  string `xml:"ResourceRecordSet>ResourceRecords>ResourceRecord>Value"`
}

type route53ChangeInfo struct {
	ID     string `xml:"ChangeInfo>Id"`
	Status string `xml:"ChangeInfo>Status"`
}

func (r *Route53) SetTXT(ctx context.Context, fqdn, value string) error {
	id, err := r.change(ctx, "UPSERT", fqdn, value)
	if err != nil {
		return err
	}
	return r.waitInSync(ctx, id)
}

func (r *Route53) CleanupTXT(ctx context.Context, fqdn, value string) error {
	// No waitInSync: nothing depends on how fast a deletion propagates.
	_, err := r.change(ctx, "DELETE", fqdn, value)
	return err
}

// change submits one UPSERT or DELETE for the TXT record and returns the
// change ID.
func (r *Route53) change(ctx context.Context, action, fqdn, value string) (string, error) {
	body := route53Change{
		Xmlns: "https://route53.amazonaws.com/doc/2013-04-01/",
		Changes: []route53Record{{
			Action: action,
			Name:   fqdn,
			Type:   "TXT",
			TTL:    route53TTL,
			// Route 53 stores TXT record data quoted. The values this
			// solver writes are base64url challenge digests, which cannot
			// contain quotes or backslashes.
			Value: `"` + value + `"`,
		}},
	}

	payload, err := xml.Marshal(body)
	if err != nil {
		return "", err
	}
	var info route53ChangeInfo
	if err := r.call(ctx, "POST", "/2013-04-01/hostedzone/"+r.zoneID+"/rrset/", payload, &info); err != nil {
		return "", fmt.Errorf("route53 %s %s: %w", action, fqdn, err)
	}
	return strings.TrimPrefix(info.ID, "/change/"), nil
}

// waitInSync polls GetChange until Route 53 reports the change applied on
// all its authoritative servers, which is the propagation guarantee
// SetTXT promises.
func (r *Route53) waitInSync(ctx context.Context, changeID string) error {
	for {
		var info route53ChangeInfo
		if err := r.call(ctx, "GET", "/2013-04-01/change/"+changeID, nil, &info); err != nil {
			return fmt.Errorf("route53 GetChange: %w", err)
		}
		if info.Status == "INSYNC" {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("route53 change %s not INSYNC: %w", changeID, context.Cause(ctx))
		case <-time.After(route53PollInterval):
		}
	}
}

func (r *Route53) call(ctx context.Context, method, path string, payload []byte, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, r.endpoint+path, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/xml")
	}
	// Route 53 is a global service; its SigV4 region is us-east-1.
	signV4(req, payload, r.accessKey, r.secretKey, r.sessionToken, "us-east-1", "route53", time.Now())

	resp, err := r.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		// The body names the actual problem (bad signature, missing
		// permission, malformed batch); a bare status code does not.
		return fmt.Errorf("status %d: %s", resp.StatusCode, respBody)
	}
	return xml.Unmarshal(respBody, out)
}
