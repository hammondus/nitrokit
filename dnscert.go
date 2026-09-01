package nitrokit

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
)

// dnsCert obtains and renews one wildcard certificate through the ACME
// DNS-01 challenge, which autocert does not implement. It is deliberately
// not exported: consumers reach it through RunTLS by listing a wildcard
// in ACME.Hosts and providing a DNSSolver.
type dnsCert struct {
	domain   string // "*.example.com"
	base     string // "example.com"
	solver   DNSSolver
	cacheDir string
	email    string

	// directoryURL is acme.LetsEncryptURL outside tests.
	directoryURL string

	// logf carries renewal failures to the operator. Renewal runs in the
	// background with no request to fail, so without this a broken
	// renewal stays invisible until the certificate expires.
	logf func(format string, args ...any)

	mu   sync.Mutex
	cert *tls.Certificate
}

const (
	// dnsRenewBefore matches autocert's default: renew in the last third
	// of a 90-day Let's Encrypt certificate's life.
	dnsRenewBefore      = 30 * 24 * time.Hour
	dnsRenewInterval    = 12 * time.Hour
	dnsRetryInterval    = time.Hour
	dnsObtainTimeout    = 15 * time.Minute
	acmeAccountKeyFile  = "acme_account+key" // shared with autocert's DirCache
	dnsCleanupTimeout   = time.Minute
	dnsWaitAuthzTimeout = 5 * time.Minute
)

func newDNSCert(domain string, solver DNSSolver, cacheDir, email string, logf func(string, ...any)) *dnsCert {
	m := &dnsCert{
		domain:       domain,
		base:         strings.TrimPrefix(domain, "*."),
		solver:       solver,
		cacheDir:     cacheDir,
		email:        email,
		directoryURL: acme.LetsEncryptURL,
		logf:         logf,
	}
	// A cached certificate from a previous run serves immediately; any
	// load problem just means the renew loop obtains a fresh one.
	if cert, err := m.load(); err == nil {
		m.cert = cert
	}
	return m
}

// matches reports whether a TLS server name is covered by the wildcard:
// exactly one extra label, per certificate matching rules.
func (m *dnsCert) matches(serverName string) bool {
	name := strings.ToLower(strings.TrimSuffix(serverName, "."))
	label, rest, ok := strings.Cut(name, ".")
	return ok && label != "" && rest == m.base
}

// certificate hands the current certificate to a TLS handshake. It never
// obtains one inline: issuance waits on DNS propagation and takes
// minutes, which no handshake survives, so a missing certificate is an
// error and the renew loop is the only issuer.
func (m *dnsCert) certificate() (*tls.Certificate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cert == nil {
		return nil, fmt.Errorf("nitrokit: certificate for %s not yet obtained", m.domain)
	}
	if time.Now().After(m.cert.Leaf.NotAfter) {
		return nil, fmt.Errorf("nitrokit: certificate for %s expired %s", m.domain, m.cert.Leaf.NotAfter.Format(time.RFC3339))
	}
	return m.cert, nil
}

// renewLoop obtains the certificate if missing and keeps it renewed. Run
// it in a goroutine; it exits when ctx is cancelled.
func (m *dnsCert) renewLoop(ctx context.Context) {
	for {
		next := dnsRenewInterval
		if err := m.ensure(ctx); err != nil {
			if ctx.Err() != nil {
				return
			}
			m.logf("nitrokit: certificate for %s: %v", m.domain, err)
			next = dnsRetryInterval
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(next):
		}
	}
}

func (m *dnsCert) ensure(ctx context.Context) error {
	m.mu.Lock()
	cert := m.cert
	m.mu.Unlock()
	if cert != nil && time.Until(cert.Leaf.NotAfter) > dnsRenewBefore {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, dnsObtainTimeout)
	defer cancel()
	return m.obtain(ctx)
}

// obtain runs one full ACME order: authorize via DNS-01, finalize with a
// fresh key and CSR, persist, and swap the certificate in.
func (m *dnsCert) obtain(ctx context.Context) error {
	client, err := m.acmeClient(ctx)
	if err != nil {
		return err
	}

	order, err := client.AuthorizeOrder(ctx, acme.DomainIDs(m.domain))
	if err != nil {
		return fmt.Errorf("order: %w", err)
	}
	for _, zurl := range order.AuthzURLs {
		if err := m.solveAuthorization(ctx, client, zurl); err != nil {
			return err
		}
	}

	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		DNSNames: []string{m.domain},
	}, certKey)
	if err != nil {
		return err
	}
	der, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return fmt.Errorf("finalize: %w", err)
	}
	leaf, err := x509.ParseCertificate(der[0])
	if err != nil {
		return err
	}
	cert := &tls.Certificate{Certificate: der, PrivateKey: certKey, Leaf: leaf}

	if err := m.store(certKey, der); err != nil {
		return err
	}
	m.mu.Lock()
	m.cert = cert
	m.mu.Unlock()
	return nil
}

// solveAuthorization proves control of one name: place the TXT record,
// tell the CA to look, wait for the verdict, remove the record.
// Authorizations are handled one at a time, which keeps the solver
// contract to a single live record per name — an UPSERT-based solver
// would otherwise overwrite a sibling challenge at the same
// _acme-challenge name.
func (m *dnsCert) solveAuthorization(ctx context.Context, client *acme.Client, zurl string) error {
	authz, err := client.GetAuthorization(ctx, zurl)
	if err != nil {
		return fmt.Errorf("authorization: %w", err)
	}
	if authz.Status == acme.StatusValid {
		return nil
	}
	var chal *acme.Challenge
	for _, c := range authz.Challenges {
		if c.Type == "dns-01" {
			chal = c
			break
		}
	}
	if chal == nil {
		return fmt.Errorf("%s: certificate authority offered no dns-01 challenge", m.domain)
	}

	record, err := client.DNS01ChallengeRecord(chal.Token)
	if err != nil {
		return err
	}
	// The identifier is the bare domain even for a wildcard order; the
	// challenge record never carries the "*.".
	fqdn := "_acme-challenge." + authz.Identifier.Value
	if err := m.solver.SetTXT(ctx, fqdn, record); err != nil {
		return fmt.Errorf("set TXT %s: %w", fqdn, err)
	}
	defer func() {
		// Clean up even when ctx is already cancelled: a leftover record
		// is harmless to serving but clutters the zone.
		cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), dnsCleanupTimeout)
		defer cancel()
		if err := m.solver.CleanupTXT(cctx, fqdn, record); err != nil {
			m.logf("nitrokit: cleanup TXT %s: %v", fqdn, err)
		}
	}()

	if _, err := client.Accept(ctx, chal); err != nil {
		return fmt.Errorf("accept challenge: %w", err)
	}
	wctx, cancel := context.WithTimeout(ctx, dnsWaitAuthzTimeout)
	defer cancel()
	if _, err := client.WaitAuthorization(wctx, zurl); err != nil {
		return fmt.Errorf("validate %s: %w", fqdn, err)
	}
	return nil
}

// acmeClient builds a client on the shared account key, registering the
// account if the CA does not know it yet.
func (m *dnsCert) acmeClient(ctx context.Context) (*acme.Client, error) {
	key, err := m.accountKey()
	if err != nil {
		return nil, err
	}
	client := &acme.Client{Key: key, DirectoryURL: m.directoryURL}
	var contact []string
	if m.email != "" {
		contact = []string{"mailto:" + m.email}
	}
	_, err = client.Register(ctx, &acme.Account{Contact: contact}, acme.AcceptTOS)
	if err != nil && !errors.Is(err, acme.ErrAccountAlreadyExists) {
		return nil, fmt.Errorf("register: %w", err)
	}
	return client, nil
}

// accountKey loads or creates the ACME account key. The file name and
// PEM format match autocert's DirCache entry, so the wildcard manager
// and autocert share one CA account.
func (m *dnsCert) accountKey() (crypto.Signer, error) {
	path := filepath.Join(m.cacheDir, acmeAccountKeyFile)
	if data, err := os.ReadFile(path); err == nil {
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, fmt.Errorf("%s: not PEM", path)
		}
		return x509.ParseECPrivateKey(block.Bytes)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	data := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	if err := os.MkdirAll(m.cacheDir, 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return nil, err
	}
	return key, nil
}

func (m *dnsCert) certPath() string {
	return filepath.Join(m.cacheDir, strings.ReplaceAll(m.domain, "*", "_wildcard")+".pem")
}

// store persists the key and chain as one PEM file, written to a
// temporary name first so a crash mid-write cannot leave a truncated
// certificate to load on the next start.
func (m *dnsCert) store(key *ecdsa.PrivateKey, der [][]byte) error {
	if err := os.MkdirAll(m.cacheDir, 0o700); err != nil {
		return err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	var data []byte
	data = append(data, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})...)
	for _, d := range der {
		data = append(data, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: d})...)
	}
	tmp, err := os.CreateTemp(m.cacheDir, "tmp-cert-")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), m.certPath())
}

func (m *dnsCert) load() (*tls.Certificate, error) {
	data, err := os.ReadFile(m.certPath())
	if err != nil {
		return nil, err
	}
	var key *ecdsa.PrivateKey
	var der [][]byte
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		switch block.Type {
		case "EC PRIVATE KEY":
			if key, err = x509.ParseECPrivateKey(block.Bytes); err != nil {
				return nil, err
			}
		case "CERTIFICATE":
			der = append(der, block.Bytes)
		}
	}
	if key == nil || len(der) == 0 {
		return nil, errors.New("cached certificate file is incomplete")
	}
	leaf, err := x509.ParseCertificate(der[0])
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{Certificate: der, PrivateKey: key, Leaf: leaf}, nil
}
