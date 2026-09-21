package tun

import (
	"context"
	M "github.com/sagernet/sing/common/metadata"
	"net/netip"
	"sync"
	"testing"
	"time"
)

type collisionHandler struct{ Handler }

func (*collisionHandler) PrepareConnection(string, M.Socksaddr, M.Socksaddr, DirectRouteContext, time.Duration) (DirectRouteDestination, error) {
	return nil, nil
}

func TestNATConcurrentSameTupleAndWrap(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	nat := NewNat(ctx, time.Hour)
	source := netip.MustParseAddrPort("192.0.2.2:49803")
	destination := netip.MustParseAddrPort("198.51.100.10:443")
	handler := new(collisionHandler)
	ports := make(chan uint16, 32)
	var group sync.WaitGroup
	for i := 0; i < 32; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			p, e := nat.Lookup(source, destination, handler)
			if e != nil {
				t.Error(e)
			}
			ports <- p
		}()
	}
	group.Wait()
	close(ports)
	for p := range ports {
		if p != 10000 {
			t.Errorf("duplicate mapping: %d", p)
		}
	}
	nat.portIndex = 65535
	last, e := nat.Lookup(source, netip.MustParseAddrPort("203.0.113.20:443"), handler)
	if e != nil || last != 65535 {
		t.Fatal(last, e)
	}
	wrapped, e := nat.Lookup(source, netip.MustParseAddrPort("203.0.113.21:443"), handler)
	if e != nil || wrapped != 10001 {
		t.Fatal("wrap reused occupied port", wrapped, e)
	}
	if nat.LookupBack(10000).Destination != destination {
		t.Fatal("wrap overwrote live session")
	}
}

func TestNATExpiryKeepsOtherDestination(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	nat := NewNat(ctx, time.Hour)
	source := netip.MustParseAddrPort("192.0.2.2:49803")
	first := netip.MustParseAddrPort("198.51.100.10:443")
	second := netip.MustParseAddrPort("203.0.113.20:443")
	a, _ := nat.Lookup(source, first, new(collisionHandler))
	b, _ := nat.Lookup(source, second, new(collisionHandler))
	old := nat.LookupBack(a)
	old.Lock()
	old.LastActive = time.Now().Add(-2 * time.Hour)
	old.Unlock()
	nat.checkTimeout()
	if nat.LookupBack(a) != nil {
		t.Fatal("expired entry retained")
	}
	again, e := nat.Lookup(source, second, new(collisionHandler))
	if e != nil || again != b || nat.LookupBack(b).Destination != second {
		t.Fatal("expiry removed other destination", again, e)
	}
}

// Android can reuse a source port when the remote destination differs.
func TestNATSameSourceDifferentDestination(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	nat := NewNat(ctx, time.Minute)
	source := netip.MustParseAddrPort("192.0.2.2:49803")
	first := netip.MustParseAddrPort("198.51.100.10:443")
	second := netip.MustParseAddrPort("203.0.113.20:443")
	handler := new(collisionHandler)
	a, err := nat.Lookup(source, first, handler)
	if err != nil {
		t.Fatal(err)
	}
	b, err := nat.Lookup(source, second, handler)
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatalf("different TCP tuples alias NAT port %d; second reverse destination is %s instead of %s", a, nat.LookupBack(b).Destination, second)
	}
	if nat.LookupBack(a).Destination != first || nat.LookupBack(b).Destination != second {
		t.Fatal("reverse NAT destination corrupted")
	}
	again, err := nat.Lookup(source, first, handler)
	if err != nil || again != a {
		t.Fatal("same tuple did not preserve mapping")
	}
}
