package tun

import (
	"net"
	"syscall"

	"github.com/sagernet/sing/common/control"
	M "github.com/sagernet/sing/common/metadata"
)

// Bound consecutive invalidations before a successful Accept. This prevents
// an invalid kernel/network state from turning recovery into a busy loop.
const tcpListenerRebindLimit = 3

func (s *System) rebindTCPListener(old net.Listener) (net.Listener, error) {
	s.listenerAccess.Lock()
	defer s.listenerAccess.Unlock()
	if old == nil || s.listenerCloseStarted.Load() || s.ctx == nil || s.ctx.Err() != nil {
		return nil, net.ErrClosed
	}
	network := ""
	port := uint16(0)
	switch old {
	case s.tcpListener:
		network, port = "tcp4", s.tcpPort
	case s.tcpListener6:
		network, port = "tcp6", s.tcpPort6
	default:
		return nil, net.ErrClosed
	}
	address := old.Addr().String()
	_ = old.Close()
	var config net.ListenConfig
	if s.bindInterface {
		config.Control = control.Append(config.Control, func(network, address string, conn syscall.RawConn) error {
			if err := control.BindToInterface0(s.interfaceFinder, conn, network, address, s.tunName, -1, true); err != nil {
				s.logger.Warn("bind forwarder to interface: ", err)
			}
			return nil
		})
	}
	replacement, err := config.Listen(s.ctx, network, address)
	if err != nil {
		return nil, err
	}
	// The port is the reverse-NAT key. A fallback/random port would corrupt
	// existing mappings; canceled/closed generations cannot publish a new owner.
	if s.listenerCloseStarted.Load() || s.ctx.Err() != nil || M.SocksaddrFromNet(replacement.Addr()).Port != port {
		_ = replacement.Close()
		return nil, net.ErrClosed
	}
	if network == "tcp4" {
		s.tcpListener = replacement
	} else {
		s.tcpListener6 = replacement
	}
	return replacement, nil
}
