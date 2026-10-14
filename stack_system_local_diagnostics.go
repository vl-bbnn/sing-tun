//go:build wlt_tun_local_diagnostics

package tun

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/sagernet/sing-tun/internal/gtcpip/header"
	M "github.com/sagernet/sing/common/metadata"
)

// Diagnostic builds only. Budgets are independent so packet chatter cannot
// suppress listener retirement or the original route-rejection observation.
const localTCPPacketBudget = 32
const localTCPEventBudget = 64

var localTCPLifetime atomic.Uint64

type localTCPDiagnosticState struct {
	mu                        sync.Mutex
	id                        uint64
	packets, events, sequence uint32
	listener4, listener6      uint16
}

func localTCPErrorClass(err error) string {
	switch {
	case err == nil:
		return "none"
	case errors.Is(err, ErrDrop):
		return "drop"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline"
	case errors.Is(err, net.ErrClosed):
		return "closed"
	default:
		var number syscall.Errno
		if errors.As(err, &number) {
			return fmt.Sprintf("errno_%d", uint64(number))
		}
		return "other"
	}
}

func (s *System) observeLocalTCP(event string, source, destination netip.AddrPort, flags uint16, reason string) {
	if s.logger == nil {
		return
	}
	state := &s.localTCPDiagnostic
	state.mu.Lock()
	if state.id == 0 {
		state.id = localTCPLifetime.Add(1)
	}
	if event == "ipv4_listener_ready" {
		state.listener4 = flags
		flags = 0
	}
	if event == "ipv6_listener_ready" {
		state.listener6 = flags
		flags = 0
	}
	packet := event == "ipv4_syn" || event == "ipv4_rst"
	if packet {
		if state.packets >= localTCPPacketBudget {
			state.mu.Unlock()
			return
		}
		state.packets++
	} else {
		if state.events >= localTCPEventBudget {
			state.mu.Unlock()
			return
		}
		state.events++
	}
	state.sequence++
	id, sequence := state.id, state.sequence
	listener4, listener6 := state.listener4, state.listener6
	state.mu.Unlock()
	s.logger.Info("WLT local TCP diagnostic event=", event, " lifetime=", id, " pid=", os.Getpid(), " observation=", sequence,
		" listener4=", listener4, " listener6=", listener6, " source=", source, " destination=", destination,
		" flags=", flags, " reason=", reason)
}

func (s *System) observeLocalTCPPacket(ip header.IPv4, tcp header.TCP) {
	event := ""
	if tcp.Flags()&header.TCPFlagRst != 0 {
		event = "ipv4_rst"
	} else if tcp.Flags()&header.TCPFlagSyn != 0 {
		event = "ipv4_syn"
	}
	if event == "" {
		return
	}
	s.observeLocalTCP(event, netip.AddrPortFrom(ip.SourceAddr(), tcp.SourcePort()), netip.AddrPortFrom(ip.DestinationAddr(), tcp.DestinationPort()), uint16(tcp.Flags()), "none")
}

// Record the listener address/family and bounded syscall number, not raw error
// text. An Accept error can now recover, so it is not called an accept exit.
func (s *System) observeLocalTCPAcceptError(listener net.Listener, err error) {
	source := netip.AddrPort{}
	if listener != nil {
		source = M.SocksaddrFromNet(listener.Addr()).AddrPort()
	}
	s.observeLocalTCP("accept_error", source, netip.AddrPort{}, 0, localTCPErrorClass(err))
}
