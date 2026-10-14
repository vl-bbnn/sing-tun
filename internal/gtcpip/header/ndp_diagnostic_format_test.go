package header

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
)

func TestNDPInvalidIPv6DiagnosticIsCanonicalAndWrapped(t *testing.T) {
	o := NDPRecursiveDNSServer(make([]byte, minNDPRecursiveDNSServerBodySize))
	address := netip.MustParseAddr("ff02::1").As16()
	copy(o[ndpRecursiveDNSServerAddressesOffset:], address[:])
	_, err := o.Addresses()
	if !errors.Is(err, ErrNDPOptMalformedBody) || !strings.Contains(err.Error(), "ff02::1") || strings.Contains(err.Error(), "%!") {
		t.Fatalf("invalid IPv6 diagnostic lost canonical address or wrapping: %v", err)
	}
}
func TestNDPIPv6ValidationDoesNotModifyWireBytes(t *testing.T) {
	o := NDPRecursiveDNSServer(make([]byte, minNDPRecursiveDNSServerBodySize))
	address := netip.MustParseAddr("2001:db8::1").As16()
	copy(o[ndpRecursiveDNSServerAddressesOffset:], address[:])
	before := string(o)
	_, err := o.Addresses()
	if err != nil || string(o) != before {
		t.Fatalf("valid unicast validation changed wire bytes: %v", err)
	}
}
