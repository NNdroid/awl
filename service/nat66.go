package service

import (
	"net"

	"github.com/anywherelan/awl/vpn"
)

// GatewayIPv6Forwarder handles IPv6 gateway forwarding on platforms where
// kernel-level IPv6 NAT is not available (Windows). When set on the Tunnel,
// IPv6 packets tagged GatewayDirForward are diverted to ForwardIPv6 instead
// of being written to TUN. The forwarder proxies them via native Go sockets
// and injects return traffic back into the tunnel.
//
// On Linux, kernel ip6tables MASQUERADE handles IPv6 NAT natively, so no
// forwarder is needed (nil).
type GatewayIPv6Forwarder interface {
	// ForwardIPv6 handles an IPv6 packet that a gateway client asked us to
	// forward to the internet. packet.Src is the client's awl IPv6 address,
	// packet.Dst is the internet destination. clientIPv4 identifies the peer
	// for routing the return packet back.
	//
	// The forwarder takes ownership of the packet (returns it to the device
	// pool when done). The caller must NOT use the packet after this call.
	ForwardIPv6(packet *vpn.Packet, clientIPv4 net.IP)

	Close() error
}

// nat66ReturnFunc is called by the NAT66 engine to send a return packet back
// to a gateway client. The engine constructs a complete IPv6 packet; this
// function routes it to the correct VpnPeer.
type nat66ReturnFunc func(packet *vpn.Packet, clientIPv4 net.IP)
