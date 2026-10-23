package httpapi

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// clientIP returns the address of the client. X-Forwarded-For is honoured
// only when the direct peer is a trusted proxy, and is read right to left
// so that a client cannot spoof its address by sending the header itself.
func clientIP(r *http.Request, trusted []netip.Prefix) netip.Addr {
	peer := parseAddr(r.RemoteAddr)
	if !isTrusted(peer, trusted) {
		return peer
	}
	hops := r.Header.Values("X-Forwarded-For")
	addr := peer
	for i := len(hops) - 1; i >= 0; i-- {
		parts := strings.Split(hops[i], ",")
		for j := len(parts) - 1; j >= 0; j-- {
			a, err := netip.ParseAddr(strings.TrimSpace(parts[j]))
			if err != nil {
				return addr
			}
			addr = a.Unmap()
			if !isTrusted(addr, trusted) {
				return addr
			}
		}
	}
	return addr
}

func parseAddr(hostport string) netip.Addr {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		host = hostport
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	return a.Unmap()
}

func isTrusted(a netip.Addr, trusted []netip.Prefix) bool {
	for _, p := range trusted {
		if p.Contains(a) {
			return true
		}
	}
	return false
}
