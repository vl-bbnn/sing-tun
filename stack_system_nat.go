package tun

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type TCPNat struct {
	timeout    time.Duration
	portIndex  uint16
	portAccess sync.RWMutex
	addrAccess sync.RWMutex
	addrMap    map[tcpSessionKey]uint16
	portMap    map[uint16]*TCPSession
}

type tcpSessionKey struct {
	Source      netip.AddrPort
	Destination netip.AddrPort
}

type TCPSession struct {
	sync.Mutex
	Source      netip.AddrPort
	Destination netip.AddrPort
	LastActive  time.Time
}

func NewNat(ctx context.Context, timeout time.Duration) *TCPNat {
	natMap := &TCPNat{
		timeout:   timeout,
		portIndex: 10000,
		addrMap:   make(map[tcpSessionKey]uint16),
		portMap:   make(map[uint16]*TCPSession),
	}
	go natMap.loopCheckTimeout(ctx)
	return natMap
}

func (n *TCPNat) loopCheckTimeout(ctx context.Context) {
	ticker := time.NewTicker(n.timeout)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			n.checkTimeout()
		case <-ctx.Done():
			return
		}
	}
}

func (n *TCPNat) checkTimeout() {
	now := time.Now()
	n.portAccess.Lock()
	defer n.portAccess.Unlock()
	n.addrAccess.Lock()
	defer n.addrAccess.Unlock()
	for natPort, session := range n.portMap {
		session.Lock()
		if now.Sub(session.LastActive) > n.timeout {
			delete(n.addrMap, tcpSessionKey{session.Source, session.Destination})
			delete(n.portMap, natPort)
		}
		session.Unlock()
	}
}

func (n *TCPNat) LookupBack(port uint16) *TCPSession {
	n.portAccess.RLock()
	session := n.portMap[port]
	n.portAccess.RUnlock()
	if session != nil {
		session.Lock()
		if time.Since(session.LastActive) > time.Second {
			session.LastActive = time.Now()
		}
		session.Unlock()
	}
	return session
}

func (n *TCPNat) Lookup(source netip.AddrPort, destination netip.AddrPort, handler Handler) (uint16, error) {
	key := tcpSessionKey{source, destination}
	n.addrAccess.RLock()
	port, loaded := n.addrMap[key]
	n.addrAccess.RUnlock()
	if loaded {
		return port, nil
	}
	_, pErr := handler.PrepareConnection(N.NetworkTCP, M.SocksaddrFromNetIP(source), M.SocksaddrFromNetIP(destination), nil, 0)
	if pErr != nil {
		return 0, pErr
	}
	// Publish both directions atomically, using the expiry lock order. A
	// concurrent retransmission can finish PrepareConnection at the same time.
	n.portAccess.Lock()
	defer n.portAccess.Unlock()
	n.addrAccess.Lock()
	defer n.addrAccess.Unlock()
	if port, loaded = n.addrMap[key]; loaded {
		return port, nil
	}
	nextPort := n.portIndex
	for checked := 0; ; checked++ {
		if checked >= 65536-10000 {
			return 0, errors.New("TCP NAT port capacity exhausted")
		}
		if nextPort < 10000 {
			nextPort = 10000
		}
		if _, occupied := n.portMap[nextPort]; !occupied {
			break
		}
		nextPort++
	}
	n.portIndex = nextPort + 1
	n.addrMap[key] = nextPort
	n.portMap[nextPort] = &TCPSession{
		Source:      source,
		Destination: destination,
		LastActive:  time.Now(),
	}
	return nextPort, nil
}
