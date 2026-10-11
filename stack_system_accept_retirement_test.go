package tun

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type acceptFixtureConn struct {
	net.Conn
	peer *net.TCPAddr
}

func (c *acceptFixtureConn) RemoteAddr() net.Addr { return c.peer }

type acceptFixtureListener struct{ conn net.Conn }

func (l *acceptFixtureListener) Accept() (net.Conn, error) {
	if l.conn == nil {
		return nil, io.EOF
	}
	c := l.conn
	l.conn = nil
	return c, nil
}
func (l *acceptFixtureListener) Close() error { return nil }
func (l *acceptFixtureListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 443}
}

func TestSystemAcceptUnknownSessionClosesConn(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	s := &System{tcpNat: &TCPNat{}, logger: logger.NOP()}
	listener := &acceptFixtureListener{conn: &acceptFixtureConn{Conn: server, peer: &net.TCPAddr{IP: net.ParseIP("192.0.2.2"), Port: 50000}}}
	s.acceptLoop(listener)
	client.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	_, err := client.Read(make([]byte, 1))
	if !errors.Is(err, io.EOF) {
		t.Fatalf("unknown_connection_remained_open: expected EOF, got %v", err)
	}
}

type acceptFixtureHandler struct {
	t                   *testing.T
	source, destination M.Socksaddr
	done                chan error
}

func (h *acceptFixtureHandler) PrepareConnection(string, M.Socksaddr, M.Socksaddr, DirectRouteContext, time.Duration) (DirectRouteDestination, error) {
	panic("unexpected prepare")
}
func (h *acceptFixtureHandler) NewPacketConnectionEx(context.Context, N.PacketConn, M.Socksaddr, M.Socksaddr, N.CloseHandlerFunc) {
	panic("unexpected UDP")
}
func (h *acceptFixtureHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	defer conn.Close()
	if source != h.source || destination != h.destination {
		h.done <- errors.New("valid NAT mapping changed")
		return
	}
	_, err := conn.Write([]byte("original-body"))
	h.done <- err
}
func TestSystemAcceptKnownSessionPreservesOriginalConn(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	source := netip.MustParseAddrPort("192.0.2.2:23456")
	destination := netip.MustParseAddrPort("198.51.100.2:443")
	handler := &acceptFixtureHandler{t: t, source: M.SocksaddrFromNetIP(source), destination: M.SocksaddrFromNetIP(destination), done: make(chan error, 1)}
	s := &System{ctx: context.Background(), tcpNat: &TCPNat{portMap: map[uint16]*TCPSession{50000: {Source: source, Destination: destination, LastActive: time.Now()}}}, logger: logger.NOP(), handler: handler}
	listener := &acceptFixtureListener{conn: &acceptFixtureConn{Conn: server, peer: &net.TCPAddr{IP: net.ParseIP("192.0.2.2"), Port: 50000}}}
	s.acceptLoop(listener)
	client.SetReadDeadline(time.Now().Add(time.Second))
	body := make([]byte, len("original-body"))
	_, err := io.ReadFull(client, body)
	if err != nil || string(body) != "original-body" {
		t.Fatalf("valid connection prematurely closed: body=%q err=%v", body, err)
	}
	select {
	case err := <-handler.done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("valid handler did not finish")
	}
}
