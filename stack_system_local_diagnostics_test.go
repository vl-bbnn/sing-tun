//go:build wlt_tun_local_diagnostics

package tun

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/sagernet/sing-tun/internal/gtcpip/header"
	"github.com/sagernet/sing/common/logger"
)

type localTCPRecorder struct {
	logger.Logger
	mu    sync.Mutex
	lines []string
}

func (l *localTCPRecorder) Info(args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, fmt.Sprint(args...))
}
func TestLocalTCPDiagnosticBoundedConcurrentLifecycle(t *testing.T) {
	l := &localTCPRecorder{Logger: logger.NOP()}
	s := &System{logger: l, tcpPort: 12345, tcpPort6: 23456}
	var wg sync.WaitGroup
	for i := 0; i < 512; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); s.observeLocalTCP("ipv4_syn", netip.AddrPort{}, netip.AddrPort{}, 2, "none") }()
	}
	wg.Wait()
	s.observeLocalTCP("accept_exit", netip.AddrPort{}, netip.AddrPort{}, 0, "closed")
	if len(l.lines) != localTCPPacketBudget+1 || !strings.Contains(l.lines[len(l.lines)-1], "event=accept_exit") {
		t.Fatalf("packet chatter starved lifecycle: %d", len(l.lines))
	}
	for i := 0; i < 256; i++ {
		s.observeLocalTCP("nat_prepare_error", netip.AddrPort{}, netip.AddrPort{}, 0, "other")
	}
	if len(l.lines) != localTCPPacketBudget+localTCPEventBudget {
		t.Fatal("unbounded diagnostics")
	}
	another := &System{logger: logger.NOP()}
	another.observeLocalTCP("close_called", netip.AddrPort{}, netip.AddrPort{}, 0, "none")
	if another.localTCPDiagnostic.id == s.localTCPDiagnostic.id || s.localTCPDiagnostic.id == 0 {
		t.Fatal("lifetime collision")
	}
}
func TestLocalTCPDiagnosticReadyStateRace(t *testing.T) {
	l := &localTCPRecorder{Logger: logger.NOP()}
	s := &System{logger: l}
	var wg sync.WaitGroup
	for i := 0; i < 128; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			s.observeLocalTCP("ipv4_listener_ready", netip.AddrPort{}, netip.AddrPort{}, 12345, "none")
		}()
		go func() {
			defer wg.Done()
			s.observeLocalTCP("ipv6_listener_ready", netip.AddrPort{}, netip.AddrPort{}, 23456, "none")
		}()
	}
	wg.Wait()
	if s.localTCPDiagnostic.listener4 != 12345 || s.localTCPDiagnostic.listener6 != 23456 || len(l.lines) != localTCPEventBudget {
		t.Fatal("ready state not safely retained/bounded")
	}
}
func TestLocalTCPDiagnosticErrorPrivacy(t *testing.T) {
	if localTCPErrorClass(errors.New("secret-token-sensitive-path")) != "other" || localTCPErrorClass(context.Canceled) != "canceled" || localTCPErrorClass(context.DeadlineExceeded) != "deadline" || localTCPErrorClass(ErrDrop) != "drop" {
		t.Fatal("wrong bounded error class")
	}
}
func TestLocalTCPDiagnosticPacketBytesUnchanged(t *testing.T) {
	b := make([]byte, 40)
	ip := header.IPv4(b)
	ip.Encode(&header.IPv4Fields{TotalLength: 40, Protocol: uint8(header.TCPProtocolNumber), SrcAddr: netip.MustParseAddr("192.0.2.1"), DstAddr: netip.MustParseAddr("198.51.100.1")})
	tcp := header.TCP(ip.Payload())
	tcp.Encode(&header.TCPFields{SrcPort: 30000, DstPort: 443, DataOffset: 20, Flags: header.TCPFlagSyn})
	before := string(b)
	l := &localTCPRecorder{Logger: logger.NOP()}
	s := &System{logger: l}
	s.observeLocalTCPPacket(ip, tcp)
	if string(b) != before || len(l.lines) != 1 || !strings.Contains(l.lines[0], "event=ipv4_syn") {
		t.Fatal("packet observer mutation or missing SYN")
	}
	tcp.SetFlags(uint8(header.TCPFlagAck))
	before = string(b)
	s.observeLocalTCPPacket(ip, tcp)
	if string(b) != before || len(l.lines) != 1 {
		t.Fatal("ordinary ACK observed/mutated")
	}
	tcp.SetFlags(uint8(header.TCPFlagRst))
	before = string(b)
	s.observeLocalTCPPacket(ip, tcp)
	if string(b) != before || len(l.lines) != 2 || !strings.Contains(l.lines[1], "event=ipv4_rst") {
		t.Fatal("RST lost/mutated")
	}
}

func TestLocalTCPDiagnosticErrnoAndListenerFamily(t *testing.T) {
	wrapped := &net.OpError{Op: "accept", Net: "tcp", Err: &os.SyscallError{Syscall: "accept4", Err: syscall.EINVAL}}
	if localTCPErrorClass(wrapped) != "errno_22" {
		t.Fatal("lost bounded syscall number")
	}
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	capture := &localTCPRecorder{Logger: logger.NOP()}
	s := &System{logger: capture}
	s.observeLocalTCPAcceptError(l, wrapped)
	if len(capture.lines) != 1 || !strings.Contains(capture.lines[0], "event=accept_error") || !strings.Contains(capture.lines[0], "source="+l.Addr().String()) || !strings.Contains(capture.lines[0], "reason=errno_22") {
		t.Fatal("listener identity/error not captured")
	}
}
