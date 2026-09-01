package nitrokit_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hammondus/nitrokit"
)

func TestParseTrustedProxies(t *testing.T) {
	if _, err := nitrokit.ParseTrustedProxies(" 10.0.0.0/8 , 127.0.0.1/32 ,, ::1/128 "); err != nil {
		t.Errorf("valid list rejected: %v", err)
	}
	if _, err := nitrokit.ParseTrustedProxies(""); err != nil {
		t.Errorf("empty list rejected: %v", err)
	}
	if _, err := nitrokit.ParseTrustedProxies("not-a-cidr"); err == nil {
		t.Error("rubbish accepted, want an error")
	}
}

// TestParseTrustedProxiesBareAddress pins the bare-address form: it means
// exactly that one address, nothing wider.
func TestParseTrustedProxiesBareAddress(t *testing.T) {
	p, err := nitrokit.ParseTrustedProxies("172.18.0.2, ::1")
	if err != nil {
		t.Fatalf("bare addresses rejected: %v", err)
	}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "172.18.0.2:9999"
	r.Header.Set("X-Forwarded-For", "203.0.113.9")
	if got := p.ClientIP(r).String(); got != "203.0.113.9" {
		t.Errorf("ClientIP = %s, want 203.0.113.9 (bare address should be trusted)", got)
	}
	r.RemoteAddr = "172.18.0.3:9999" // one off the trusted address
	if got := p.ClientIP(r).String(); got != "172.18.0.3" {
		t.Errorf("ClientIP = %s, want 172.18.0.3 (neighbour must not be trusted)", got)
	}
}

func TestTrustPrivateProxies(t *testing.T) {
	p := nitrokit.TrustPrivateProxies()
	trusted := []string{"127.0.0.1", "10.1.2.3", "172.20.0.2", "192.168.1.1", "169.254.10.10"}
	for _, peer := range trusted {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = peer + ":9999"
		r.Header.Set("X-Forwarded-For", "203.0.113.9")
		if got := p.ClientIP(r).String(); got != "203.0.113.9" {
			t.Errorf("peer %s: ClientIP = %s, want 203.0.113.9 (private peer should be trusted)", peer, got)
		}
	}
	// A public peer must never be trusted, or anyone on the internet
	// could spoof their own address.
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "203.0.113.50:9999"
	r.Header.Set("X-Forwarded-For", "192.0.2.1")
	if got := p.ClientIP(r).String(); got != "203.0.113.50" {
		t.Errorf("public peer honoured XFF: ClientIP = %s", got)
	}
}

func TestParseTrustedProxiesMasksHostBits(t *testing.T) {
	// 10.1.2.3/8 names the block 10.0.0.0/8. Without masking, Contains
	// matches nothing against it.
	p, err := nitrokit.ParseTrustedProxies("10.1.2.3/8")
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.9.9.9:1234"
	r.Header.Set("X-Forwarded-For", "203.0.113.7")
	if got := p.ClientIP(r).String(); got != "203.0.113.7" {
		t.Errorf("ClientIP = %s, want 203.0.113.7 (10.9.9.9 should be trusted under 10.1.2.3/8)", got)
	}
}

func TestClientIP(t *testing.T) {
	p, err := nitrokit.ParseTrustedProxies("127.0.0.1/32,172.16.0.0/12,::1/128")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		remote string
		xff    []string
		want   string
	}{
		{
			name:   "no proxy header",
			remote: "203.0.113.7:5000",
			want:   "203.0.113.7",
		},
		{
			name:   "untrusted peer forging the header is ignored",
			remote: "203.0.113.7:5000",
			xff:    []string{"192.0.2.1"},
			want:   "203.0.113.7",
		},
		{
			name:   "trusted peer, single hop",
			remote: "127.0.0.1:5000",
			xff:    []string{"203.0.113.7"},
			want:   "203.0.113.7",
		},
		{
			name:   "forged left value behind a trusted proxy is skipped",
			remote: "127.0.0.1:5000",
			xff:    []string{"192.0.2.99, 203.0.113.7"},
			want:   "203.0.113.7",
		},
		{
			name:   "chain of trusted proxies is walked from the right",
			remote: "127.0.0.1:5000",
			xff:    []string{"203.0.113.7, 172.16.0.2, 172.16.0.3"},
			want:   "203.0.113.7",
		},
		{
			name:   "hops split across multiple header values",
			remote: "127.0.0.1:5000",
			xff:    []string{"203.0.113.7", "172.16.0.2"},
			want:   "203.0.113.7",
		},
		{
			name:   "all hops trusted falls back to the peer",
			remote: "127.0.0.1:5000",
			xff:    []string{"172.16.0.2"},
			want:   "127.0.0.1",
		},
		{
			name:   "trusted peer with empty header",
			remote: "127.0.0.1:5000",
			want:   "127.0.0.1",
		},
		{
			name:   "malformed hop falls back to the peer",
			remote: "127.0.0.1:5000",
			xff:    []string{"203.0.113.7, not-an-ip"},
			want:   "127.0.0.1",
		},
		{
			name:   "IPv4-mapped IPv6 hop is unmapped",
			remote: "127.0.0.1:5000",
			xff:    []string{"::ffff:203.0.113.7"},
			want:   "203.0.113.7",
		},
		{
			name:   "IPv6 loopback peer is trusted",
			remote: "[::1]:5000",
			xff:    []string{"203.0.113.7"},
			want:   "203.0.113.7",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = tt.remote
			for _, v := range tt.xff {
				r.Header.Add("X-Forwarded-For", v)
			}
			if got := p.ClientIP(r).String(); got != tt.want {
				t.Errorf("ClientIP = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestClientIPZeroValueTrustsNoOne(t *testing.T) {
	var p nitrokit.ProxyTrust
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "127.0.0.1:5000"
	r.Header.Set("X-Forwarded-For", "203.0.113.7")
	if got := p.ClientIP(r).String(); got != "127.0.0.1" {
		t.Errorf("ClientIP = %s, want 127.0.0.1 (zero value must ignore the header)", got)
	}

	// A nil pointer is the same secure default, not a panic — a test that
	// builds a server struct without wiring the trust list should still run.
	var np *nitrokit.ProxyTrust
	if got := np.ClientIP(r).String(); got != "127.0.0.1" {
		t.Errorf("nil ClientIP = %s, want 127.0.0.1", got)
	}
}
