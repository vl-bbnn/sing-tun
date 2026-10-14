package tun

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
)

func recoveryHostSystem(t *testing.T) (*System, net.Listener, context.CancelFunc) {
	t.Helper()
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &System{ctx: ctx, logger: logger.NOP(), tcpListener: l, tcpPort: M.SocksaddrFromNet(l.Addr()).Port, tcpNat: &TCPNat{portMap: map[uint16]*TCPSession{50000: {Source: netip.MustParseAddrPort("192.0.2.1:1000"), Destination: netip.MustParseAddrPort("198.51.100.1:443"), LastActive: time.Now()}}}}
	return s, l, cancel
}
func TestListenerRecoverySamePortPreservesNatAndAcceptedBody(t *testing.T) {
	s, l, cancel := recoveryHostSystem(t)
	defer cancel()
	defer s.Close()
	originalNat := s.tcpNat
	mapping := originalNat.portMap[50000]
	address := l.Addr().String()
	client, e := net.DialTimeout("tcp4", address, time.Second)
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	accepted, e := l.Accept()
	if e != nil {
		t.Fatal(e)
	}
	defer accepted.Close()
	next, e := s.rebindTCPListener(l)
	if e != nil {
		t.Fatal(e)
	}
	if next.Addr().String() != address || s.tcpPort != M.SocksaddrFromNet(next.Addr()).Port || s.tcpNat != originalNat || s.tcpNat.portMap[50000] != mapping {
		t.Fatal("port/NAT changed")
	}
	accepted.SetDeadline(time.Now().Add(time.Second))
	client.SetDeadline(time.Now().Add(time.Second))
	sent := make(chan error, 1)
	go func() { _, e := accepted.Write([]byte("original-accepted-body")); sent <- e }()
	body := make([]byte, len("original-accepted-body"))
	if _, e = io.ReadFull(client, body); e != nil || string(body) != "original-accepted-body" {
		t.Fatalf("accepted body lost %q %v", body, e)
	}
	if e = <-sent; e != nil {
		t.Fatal(e)
	}
	fresh, e := net.DialTimeout("tcp4", address, time.Second)
	if e != nil {
		t.Fatal(e)
	}
	defer fresh.Close()
	peer, e := next.Accept()
	if e != nil {
		t.Fatal(e)
	}
	peer.Close()
	if _, e = s.rebindTCPListener(l); !errors.Is(e, net.ErrClosed) {
		t.Fatalf("stale listener reopened: %v", e)
	}
}
func TestListenerRecoveryIPv6PortAndSibling(t *testing.T) {
	s, l4, cancel := recoveryHostSystem(t)
	defer cancel()
	defer s.Close()
	l6, e := net.Listen("tcp6", "[::1]:0")
	if e != nil {
		t.Fatal(e)
	}
	s.tcpListener6 = l6
	s.tcpPort6 = M.SocksaddrFromNet(l6.Addr()).Port
	address := l6.Addr().String()
	next, e := s.rebindTCPListener(l6)
	if e != nil {
		t.Fatal(e)
	}
	if s.tcpListener != l4 || next.Addr().String() != address || s.tcpPort6 != M.SocksaddrFromNet(next.Addr()).Port {
		t.Fatal("IPv6 rebind changed sibling or port")
	}
	c, e := net.DialTimeout("tcp6", address, time.Second)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	p, e := next.Accept()
	if e != nil {
		t.Fatal(e)
	}
	p.Close()
}
func TestListenerRecoveryCancelCloseAndNilReject(t *testing.T) {
	s, l, cancel := recoveryHostSystem(t)
	defer s.Close()
	cancel()
	if _, e := s.rebindTCPListener(l); !errors.Is(e, net.ErrClosed) || s.tcpListener != l {
		t.Fatal("canceled owner replaced")
	}
	if _, e := s.rebindTCPListener(nil); !errors.Is(e, net.ErrClosed) {
		t.Fatal("nil owner admitted")
	}
	fresh, old, stop := recoveryHostSystem(t)
	defer stop()
	fresh.Close()
	if _, e := fresh.rebindTCPListener(old); !errors.Is(e, net.ErrClosed) {
		t.Fatal("closed owner reopened")
	}
}
func TestListenerRecoveryCloseRaceNoLiveResurrection(t *testing.T) {
	s, l, cancel := recoveryHostSystem(t)
	defer cancel()
	address := l.Addr().String()
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			next, e := s.rebindTCPListener(l)
			if e != nil && !errors.Is(e, net.ErrClosed) {
				t.Errorf("unexpected recovery race: %v", e)
			}
			_ = next
		}()
	}
	wg.Add(1)
	go func() { defer wg.Done(); _ = s.Close() }()
	wg.Wait()
	_ = s.Close()
	if !s.listenerCloseStarted.Load() {
		t.Fatal("Close did not seal")
	}
	conn, e := net.DialTimeout("tcp4", address, time.Second)
	if conn != nil {
		conn.Close()
		t.Fatal("listener survived Close")
	}
	if e == nil {
		t.Fatal("fresh connection after Close")
	}
}

type recoveryEOFListener struct{ net.Listener }

func (l *recoveryEOFListener) Accept() (net.Conn, error) { return nil, io.EOF }
func TestListenerRecoveryDoesNotRetryUnrelatedAcceptError(t *testing.T) {
	s, l, cancel := recoveryHostSystem(t)
	defer cancel()
	defer s.Close()
	wrapped := &recoveryEOFListener{l}
	s.tcpListener = wrapped
	s.acceptLoop(wrapped)
	if s.tcpListener != wrapped {
		t.Fatal("non-EINVAL error triggered rebind")
	}
}
