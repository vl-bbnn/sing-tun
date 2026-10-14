package tcpip

import (
	"net/netip"
	"strings"
	"testing"
)

func TestAddressDiagnosticFormatsPreserveOriginalBytes(t *testing.T) {
	for _, c := range []struct {
		address string
		prefix int
		wantPrefix, wantSubnet string
	}{
		{"192.0.2.27", 24, "192.0.2.27/24", "192.0.2.0/24"},
		{"2001:db8::27", 64, "2001:db8::27/64", "2001:db8::/64"},
	} {
		t.Run(c.address, func(t *testing.T) {
			n := netip.MustParseAddr(c.address)
			a := AddrFromSlice(n.AsSlice())
			original := string(a.AsSlice())
			prefix := AddressWithPrefix{Address: a, PrefixLen: c.prefix}
			subnet := prefix.Subnet()
			if prefix.String() != c.wantPrefix || subnet.String() != c.wantSubnet {
				t.Fatalf("malformed_address_diagnostic prefix=%q subnet=%q", prefix.String(), subnet.String())
			}
			if string(a.AsSlice()) != original {
				t.Fatal("diagnostic formatting changed original address bytes")
			}
		})
	}
}

func TestAddressMismatchPanicKeepsActualAddressesAndBytes(t *testing.T) {
	a := AddrFromSlice(netip.MustParseAddr("192.0.2.27").AsSlice())
	b := AddrFromSlice(netip.MustParseAddr("2001:db8::27").AsSlice())
	beforeA, beforeB := string(a.AsSlice()), string(b.AsSlice())
	defer func() {
		value := recover()
		text, ok := value.(string)
		if !ok || !strings.Contains(text, "192.0.2.27") || !strings.Contains(text, "2001:db8::27") || strings.Contains(text, "%!") {
			t.Fatalf("address mismatch panic lost original identity: %v", value)
		}
		if string(a.AsSlice()) != beforeA || string(b.AsSlice()) != beforeB {
			t.Fatal("panic diagnostic modified original address bytes")
		}
	}()
	a.MatchingPrefix(b)
}
