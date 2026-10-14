//go:build linux

package tun

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type recoveryKernelListener struct {
	net.Listener
	mu   sync.Mutex
	last error
}

func (l *recoveryKernelListener) Accept() (net.Conn, error) {
	c, e := l.Listener.Accept()
	if e != nil {
		l.mu.Lock()
		l.last = e
		l.mu.Unlock()
	}
	return c, e
}
func (l *recoveryKernelListener) capturedError() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.last
}

type recoveryKernelHandler struct{ done chan error }

func (*recoveryKernelHandler) PrepareConnection(string, M.Socksaddr, M.Socksaddr, DirectRouteContext, time.Duration) (DirectRouteDestination, error) {
	panic("unexpected prepare")
}
func (*recoveryKernelHandler) NewPacketConnectionEx(context.Context, N.PacketConn, M.Socksaddr, M.Socksaddr, N.CloseHandlerFunc) {
	panic("unexpected UDP")
}
func (h *recoveryKernelHandler) NewConnectionEx(ctx context.Context, c net.Conn, source, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(time.Second))
	if source != M.SocksaddrFromNetIP(netip.MustParseAddrPort("192.0.2.1:1000")) || destination != M.SocksaddrFromNetIP(netip.MustParseAddrPort("198.51.100.1:443")) {
		h.done <- errors.New("NAT metadata changed")
		return
	}
	_, e := c.Write([]byte("kernel-recovered-body"))
	h.done <- e
}
func TestKernelListenerRecoveryKeepsSamePortAfterExternalInvalidation(t *testing.T) {
	original, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer original.Close()
	address := original.Addr().String()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	handler := &recoveryKernelHandler{done: make(chan error, 1)}
	wrapped := &recoveryKernelListener{Listener: original}
	nat := NewNat(ctx, time.Minute)
	sentinel := &TCPSession{Source: netip.MustParseAddrPort("192.0.2.1:1000"), Destination: netip.MustParseAddrPort("198.51.100.1:443"), LastActive: time.Now()}
	nat.portMap[10000] = sentinel
	s := &System{ctx: ctx, logger: logger.NOP(), handler: handler, tcpListener: wrapped, tcpPort: M.SocksaddrFromNet(original.Addr()).Port, tcpNat: nat}
	defer s.Close()
	done := make(chan struct{})
	go func() { s.acceptLoop(wrapped); close(done) }()
	raw, e := original.(*net.TCPListener).SyscallConn()
	if e != nil {
		t.Fatal(e)
	}
	var invalidation error
	e = raw.Control(func(fd uintptr) { invalidation = syscall.Shutdown(int(fd), syscall.SHUT_RDWR) })
	if e != nil || invalidation != nil {
		t.Fatalf("owned invalidation failed %v %v", e, invalidation)
	}
	deadline := time.Now().Add(time.Second)
	for {
		s.listenerAccess.Lock()
		replacement := s.tcpListener
		ready := replacement != wrapped && replacement.Addr().String() == address
		s.listenerAccess.Unlock()
		if ready {
			break
		}
		select {
		case <-done:
			t.Fatal("repair still ended accept loop")
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("rebind never published")
		}
		time.Sleep(time.Millisecond)
	}
	var errno syscall.Errno
	if !errors.As(wrapped.capturedError(), &errno) || errno != syscall.EINVAL {
		t.Fatalf("not actual kernel EINVAL: %v", wrapped.capturedError())
	}
	dialer := net.Dialer{Timeout: time.Second, Control: func(network, address string, raw syscall.RawConn) error {
		var inner error
		e := raw.Control(func(fd uintptr) {
			inner = syscall.Bind(int(fd), &syscall.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}})
			if inner != nil {
				return
			}
			local, err := syscall.Getsockname(int(fd))
			if err != nil {
				inner = err
				return
			}
			port := uint16(local.(*syscall.SockaddrInet4).Port)
			if port == 10000 {
				inner = errors.New("fixture source collided with preserved sentinel")
				return
			}
			nat.portAccess.Lock()
			nat.portMap[port] = &TCPSession{Source: sentinel.Source, Destination: sentinel.Destination, LastActive: time.Now()}
			nat.portAccess.Unlock()
		})
		if e != nil {
			return e
		}
		return inner
	}}
	client, e := dialer.Dial("tcp4", address)
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	client.SetDeadline(time.Now().Add(time.Second))
	body := make([]byte, len("kernel-recovered-body"))
	if _, e = io.ReadFull(client, body); e != nil || string(body) != "kernel-recovered-body" {
		t.Fatalf("fresh recovered body %q %v", body, e)
	}
	if e = <-handler.done; e != nil {
		t.Fatal(e)
	}
	if s.tcpNat != nat || nat.portMap[10000] != sentinel || s.tcpPort != M.SocksaddrFromNet(original.Addr()).Port {
		t.Fatal("port or existing NAT replaced")
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Close failed to reap accept owner")
	}
	value, _ := json.Marshal(map[string]any{"kernel_accept_errno": int(errno), "same_port_automatic_rebind": true, "fresh_body_and_original_NAT_metadata_verified": true, "Close_reaped_owner": true, "original_stream_continuity_proven": false})
	t.Log("KERNEL_RECOVERY_PROOF " + string(value))
}
