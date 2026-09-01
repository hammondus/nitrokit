package nitrokit

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
)

// ProxyTrust decides which peers may set forwarding headers. The zero
// value trusts no one, which makes every request attribute to its TCP
// peer and ignores X-Forwarded-For entirely.
type ProxyTrust struct {
	nets []netip.Prefix
}

// ParseTrustedProxies reads a comma-separated list of CIDR blocks and
// bare addresses, such as "127.0.0.1/32,::1/128" or "172.18.0.2" for a
// proxy on the same host. Blank fields are skipped. A bare address means
// exactly that one address (/32 or /128) — it is unambiguous, and live
// configs already write it.
func ParseTrustedProxies(list string) (*ProxyTrust, error) {
	p := &ProxyTrust{}
	for field := range strings.SplitSeq(list, ",") {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		n, err := netip.ParsePrefix(field)
		if err != nil {
			a, aerr := netip.ParseAddr(field)
			if aerr != nil {
				return nil, fmt.Errorf("trusted proxy %q: %w", field, err)
			}
			a = a.Unmap()
			n = netip.PrefixFrom(a, a.BitLen())
		}
		// Masked, so "10.1.2.3/8" names the block 10.0.0.0/8 instead of a
		// prefix Contains matches nothing against.
		p.nets = append(p.nets, n.Masked())
	}
	return p, nil
}

// TrustPrivateProxies returns a trust list covering the loopback,
// private (RFC 1918 and ULA), and link-local ranges — the "any peer on
// the local or docker network is my proxy" posture most house
// deployments hand-rolled before this module existed.
//
// It is a named constructor, not the default, on purpose: the zero
// ProxyTrust trusts no one, and widening trust should be a greppable
// choice in the caller. Use it when the server only ever runs behind a
// same-host or same-compose-network proxy; when the proxy has a stable
// address, an explicit ParseTrustedProxies list is the tighter fit.
// Trusting all private space means anything that can reach the server
// from the LAN can spoof its client address, so it is wrong for a server
// that LAN clients also hit directly.
func TrustPrivateProxies() *ProxyTrust {
	p := &ProxyTrust{}
	for _, s := range []string{
		"127.0.0.0/8", "::1/128", // loopback
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", // RFC 1918
		"fc00::/7",                    // IPv6 ULA
		"169.254.0.0/16", "fe80::/10", // link-local
	} {
		p.nets = append(p.nets, netip.MustParsePrefix(s))
	}
	return p
}

func (p *ProxyTrust) trusted(a netip.Addr) bool {
	// A nil ProxyTrust trusts no one, same as the zero value: the secure
	// default should not depend on whether the caller holds a pointer.
	if p == nil || !a.IsValid() {
		return false
	}
	a = a.Unmap()
	for _, n := range p.nets {
		if n.Contains(a) {
			return true
		}
	}
	return false
}

// ClientIP returns the address to attribute a request to.
//
// X-Forwarded-For is attacker-controlled: anyone can send it. ClientIP
// honours it only when the immediate peer is a trusted proxy, then walks
// the list right to left, skipping further trusted hops. The first
// untrusted address is the client. If the peer is not trusted, the header
// is ignored.
//
// This is not only a logging concern. The leftmost value costs an
// attacker nothing to forge, and an attacker who can forge the header
// resets their own login and rate-limit buckets.
func (p *ProxyTrust) ClientIP(r *http.Request) netip.Addr {
	peer := peerAddr(r)
	if !p.trusted(peer) {
		return peer
	}
	var hops []string
	for _, v := range r.Header.Values("X-Forwarded-For") {
		for s := range strings.SplitSeq(v, ",") {
			hops = append(hops, strings.TrimSpace(s))
		}
	}
	for _, hop := range slices.Backward(hops) {
		a, err := netip.ParseAddr(hop)
		if err != nil {
			// A malformed hop means nothing to its left can be believed.
			return peer
		}
		if a = a.Unmap(); !p.trusted(a) {
			return a
		}
	}
	// Every hop is a trusted proxy, so the nearest one is the client —
	// a proxy health check probing its own upstream looks like this.
	return peer
}

// peerAddr is the address at the other end of the connection.
func peerAddr(r *http.Request) netip.Addr {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	return a.Unmap().WithZone("")
}
