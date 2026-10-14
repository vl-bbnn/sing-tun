//go:build !wlt_tun_local_diagnostics

package tun

import (
	"github.com/sagernet/sing-tun/internal/gtcpip/header"
	"net"
	"net/netip"
)

type localTCPDiagnosticState struct{}

func localTCPErrorClass(error) string                                                  { return "" }
func (*System) observeLocalTCP(string, netip.AddrPort, netip.AddrPort, uint16, string) {}
func (*System) observeLocalTCPPacket(header.IPv4, header.TCP)                          {}

func (*System) observeLocalTCPAcceptError(net.Listener, error) {}
