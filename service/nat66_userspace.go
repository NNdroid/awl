//go:build windows || darwin

package service

import (
	"encoding/binary"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ipfs/go-log/v2"
	"golang.org/x/net/ipv6"

	"github.com/anywherelan/awl/vpn"
)

const (
	// nat66UDPTimeout is how long an idle UDP NAT mapping lives.
	nat66UDPTimeout = 2 * time.Minute
	// nat66CleanupInterval is how often the cleanup goroutine runs.
	nat66CleanupInterval = 30 * time.Second
	// nat66MaxUDPEntries limits the total number of concurrent UDP mappings.
	nat66MaxUDPEntries = 4096
)

// nat66Engine implements GatewayIPv6Forwarder using userspace UDP/ICMPv6
// proxying. TCP packets trigger an ICMPv6 Destination Unreachable response
// so clients fall back to IPv4 quickly (Happy Eyeballs).
//
// Used on Windows (no kernel NAT66) and macOS (pf lacks stateful MASQUERADE
// for IPv6). On Linux, kernel ip6tables MASQUERADE handles this natively.
type nat66Engine struct {
	device   *vpn.Device
	returnFn nat66ReturnFunc
	logger   *log.ZapEventLogger

	// UDP NAT table.
	udpMu      sync.RWMutex
	udpEntries map[udp66Key]*udp66Entry

	// Shutdown.
	done     chan struct{}
	closed   atomic.Bool
	cleanupW sync.WaitGroup
}

type udp66Key struct {
	ClientIP   [net.IPv6len]byte
	ClientPort uint16
	DstIP      [net.IPv6len]byte
	DstPort    uint16
}

type udp66Entry struct {
	conn       *net.UDPConn
	clientIPv4 net.IP // for routing the return packet
	clientIPv6 net.IP // src of the original forward packet
	dstIP      net.IP // original destination
	dstPort    uint16
	clientPort uint16
	lastUsed   atomic.Int64 // UnixNano
}

func newNAT66Engine(device *vpn.Device, returnFn nat66ReturnFunc) *nat66Engine {
	e := &nat66Engine{
		device:     device,
		returnFn:   returnFn,
		logger:     log.Logger("awl/service/nat66"),
		udpEntries: make(map[udp66Key]*udp66Entry),
		done:       make(chan struct{}),
	}
	e.cleanupW.Add(1)
	go e.cleanupLoop()
	return e
}

func (e *nat66Engine) ForwardIPv6(packet *vpn.Packet, clientIPv4 net.IP) {
	defer e.device.PutTempPacket(packet)

	if e.closed.Load() {
		return
	}

	switch packet.IPProtocol {
	case vpn.IPProtocolUDP:
		e.forwardUDP(packet, clientIPv4)
	case vpn.IPProtocolICMPv6:
		e.forwardICMPv6(packet, clientIPv4)
	case vpn.IPProtocolTCP:
		e.rejectTCP(packet, clientIPv4)
	default:
		// Unsupported protocol — drop silently.
	}
}

// forwardUDP extracts the UDP payload from the IPv6 packet, sends it via a
// Go UDP socket, and starts a goroutine to read responses.
func (e *nat66Engine) forwardUDP(packet *vpn.Packet, clientIPv4 net.IP) {
	if len(packet.Packet) < ipv6.HeaderLen+8 {
		return
	}
	payload := packet.Packet[ipv6.HeaderLen:]
	srcPort := binary.BigEndian.Uint16(payload[0:2])
	dstPort := binary.BigEndian.Uint16(payload[2:4])
	udpPayload := payload[8:]

	var key udp66Key
	copy(key.ClientIP[:], packet.Src)
	key.ClientPort = srcPort
	copy(key.DstIP[:], packet.Dst)
	key.DstPort = dstPort

	e.udpMu.RLock()
	entry, exists := e.udpEntries[key]
	e.udpMu.RUnlock()

	if exists {
		entry.lastUsed.Store(time.Now().UnixNano())
		_, _ = entry.conn.Write(udpPayload)
		return
	}

	// Check entry limit.
	e.udpMu.RLock()
	count := len(e.udpEntries)
	e.udpMu.RUnlock()
	if count >= nat66MaxUDPEntries {
		e.logger.Warnf("NAT66 UDP table full (%d entries), dropping packet", count)
		return
	}

	// Create a new UDP socket to the destination.
	dstAddr := &net.UDPAddr{
		IP:   net.IP(make([]byte, net.IPv6len)),
		Port: int(dstPort),
	}
	copy(dstAddr.IP, packet.Dst)

	conn, err := net.DialUDP("udp6", nil, dstAddr)
	if err != nil {
		e.logger.Debugf("NAT66 UDP dial %s: %v", dstAddr, err)
		return
	}

	entry = &udp66Entry{
		conn:       conn,
		clientIPv4: make(net.IP, net.IPv4len),
		clientIPv6: make(net.IP, net.IPv6len),
		dstIP:      make(net.IP, net.IPv6len),
		dstPort:    dstPort,
		clientPort: srcPort,
	}
	copy(entry.clientIPv4, clientIPv4.To4())
	copy(entry.clientIPv6, packet.Src)
	copy(entry.dstIP, packet.Dst)
	entry.lastUsed.Store(time.Now().UnixNano())

	e.udpMu.Lock()
	// Double-check: another goroutine may have created the entry.
	if existing, ok := e.udpEntries[key]; ok {
		e.udpMu.Unlock()
		_ = conn.Close()
		existing.lastUsed.Store(time.Now().UnixNano())
		_, _ = existing.conn.Write(udpPayload)
		return
	}
	e.udpEntries[key] = entry
	e.udpMu.Unlock()

	// Send the payload.
	_, _ = conn.Write(udpPayload)

	// Start response reader.
	e.cleanupW.Add(1)
	go e.udpReturnLoop(key, entry)
}

// udpReturnLoop reads responses from the UDP socket and constructs return
// IPv6/UDP packets to send back to the client.
func (e *nat66Engine) udpReturnLoop(key udp66Key, entry *udp66Entry) {
	defer e.cleanupW.Done()
	defer func() {
		_ = entry.conn.Close()
		e.udpMu.Lock()
		delete(e.udpEntries, key)
		e.udpMu.Unlock()
	}()

	buf := make([]byte, vpn.MaxPacketBodySize-ipv6.HeaderLen-8)
	for {
		_ = entry.conn.SetReadDeadline(time.Now().Add(nat66UDPTimeout))
		n, err := entry.conn.Read(buf)
		if err != nil {
			return
		}
		if e.closed.Load() {
			return
		}
		entry.lastUsed.Store(time.Now().UnixNano())

		// Construct IPv6+UDP return packet.
		pkt := e.buildIPv6UDP(
			entry.dstIP, entry.dstPort,
			entry.clientIPv6, entry.clientPort,
			buf[:n],
		)
		if pkt == nil {
			continue
		}
		pkt.GatewayDir = vpn.GatewayDirReturn
		e.returnFn(pkt, entry.clientIPv4)
	}
}

// forwardICMPv6 handles ICMPv6 echo requests. For simplicity, we use a
// per-packet approach: open a raw ICMPv6 socket, send the echo request,
// read the reply, and construct the return packet.
func (e *nat66Engine) forwardICMPv6(packet *vpn.Packet, clientIPv4 net.IP) {
	if len(packet.Packet) < ipv6.HeaderLen+8 {
		return
	}
	icmpPayload := packet.Packet[ipv6.HeaderLen:]
	icmpType := icmpPayload[0]

	// Only handle echo requests (type 128).
	if icmpType != 128 {
		return
	}

	dstIP := make(net.IP, net.IPv6len)
	copy(dstIP, packet.Dst)
	srcIP := make(net.IP, net.IPv6len)
	copy(srcIP, packet.Src)
	clientIPv4Copy := make(net.IP, net.IPv4len)
	copy(clientIPv4Copy, clientIPv4.To4())

	// Make a copy of the ICMPv6 payload for the goroutine.
	icmpCopy := make([]byte, len(icmpPayload))
	copy(icmpCopy, icmpPayload)

	// Forward in a goroutine to avoid blocking the inbound handler.
	go func() {
		conn, err := net.DialIP("ip6:ipv6-icmp", nil, &net.IPAddr{IP: dstIP})
		if err != nil {
			e.logger.Debugf("NAT66 ICMPv6 dial %s: %v", dstIP, err)
			return
		}
		defer conn.Close()

		// The kernel handles ICMPv6 checksum for raw sockets.
		_, err = conn.Write(icmpCopy)
		if err != nil {
			e.logger.Debugf("NAT66 ICMPv6 write: %v", err)
			return
		}

		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		replyBuf := make([]byte, vpn.MaxPacketBodySize-ipv6.HeaderLen)
		n, err := conn.Read(replyBuf)
		if err != nil {
			return
		}

		// Construct return IPv6+ICMPv6 packet.
		pkt := e.buildIPv6Raw(dstIP, srcIP, vpn.IPProtocolICMPv6, replyBuf[:n])
		if pkt == nil {
			return
		}
		pkt.GatewayDir = vpn.GatewayDirReturn
		e.returnFn(pkt, clientIPv4Copy)
	}()
}

// rejectTCP sends an ICMPv6 Destination Unreachable (Type 1, Code 4 — Port
// Unreachable) back to the client. This causes the client's TCP stack to
// report the connection as refused, triggering a fast IPv4 fallback via
// Happy Eyeballs (RFC 6555). Without this, the client would wait for a TCP
// retransmit timeout (~seconds), degrading UX.
func (e *nat66Engine) rejectTCP(packet *vpn.Packet, clientIPv4 net.IP) {
	if len(packet.Packet) < ipv6.HeaderLen {
		return
	}

	// ICMPv6 Destination Unreachable: Type=1, Code=4 (Port Unreachable).
	// Payload: as much of the invoking packet as possible without exceeding
	// the minimum IPv6 MTU (1280).
	const (
		icmpv6TypeDstUnreachable  = 1
		icmpv6CodePortUnreachable = 4
		icmpv6HeaderLen           = 8 // type(1) + code(1) + checksum(2) + unused(4)
	)

	// Include as much of the original packet as fits in the ICMPv6 payload.
	origLen := len(packet.Packet)
	maxOrig := 1280 - ipv6.HeaderLen - icmpv6HeaderLen
	if origLen > maxOrig {
		origLen = maxOrig
	}

	icmpPayload := make([]byte, icmpv6HeaderLen+origLen)
	icmpPayload[0] = icmpv6TypeDstUnreachable
	icmpPayload[1] = icmpv6CodePortUnreachable
	// checksum bytes [2:4] = 0 (filled by RecalculateChecksum)
	// unused bytes [4:8] = 0
	copy(icmpPayload[icmpv6HeaderLen:], packet.Packet[:origLen])

	// Build the return packet: src = original dst (internet), dst = client's awl IPv6.
	pkt := e.buildIPv6Raw(packet.Dst, packet.Src, vpn.IPProtocolICMPv6, icmpPayload)
	if pkt == nil {
		return
	}
	pkt.GatewayDir = vpn.GatewayDirReturn
	e.returnFn(pkt, clientIPv4)
}

// buildIPv6UDP constructs a complete IPv6/UDP packet in a pooled Packet.
func (e *nat66Engine) buildIPv6UDP(srcIP net.IP, srcPort uint16, dstIP net.IP, dstPort uint16, payload []byte) *vpn.Packet {
	const udpHeaderLen = 8
	payloadLen := len(payload)
	udpLen := udpHeaderLen + payloadLen
	totalLen := ipv6.HeaderLen + udpLen

	if totalLen > vpn.MaxPacketBodySize {
		e.logger.Warnf("NAT66 return packet too large (%d bytes)", totalLen)
		return nil
	}

	pkt := e.device.GetTempPacket()
	// tunPacketOffset = 14 (from vpn package)
	const tunPacketOffset = 14
	ip := pkt.Buffer[tunPacketOffset : tunPacketOffset+totalLen]

	// IPv6 header.
	ip[0] = 0x60 // version=6, traffic class=0
	ip[1] = 0
	ip[2] = 0
	ip[3] = 0                                           // flow label = 0
	binary.BigEndian.PutUint16(ip[4:6], uint16(udpLen)) // payload length
	ip[6] = vpn.IPProtocolUDP                           // next header
	ip[7] = 64                                          // hop limit
	copy(ip[8:24], srcIP.To16())
	copy(ip[24:40], dstIP.To16())

	// UDP header.
	udp := ip[ipv6.HeaderLen:]
	binary.BigEndian.PutUint16(udp[0:2], srcPort)
	binary.BigEndian.PutUint16(udp[2:4], dstPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpLen))
	// checksum [6:8] = 0 for now (filled by RecalculateChecksum)
	udp[6] = 0
	udp[7] = 0
	copy(udp[8:], payload)

	pkt.Packet = ip
	pkt.IsIPv6 = true
	pkt.IPProtocol = vpn.IPProtocolUDP
	pkt.Src = ip[8:24]
	pkt.Dst = ip[24:40]
	pkt.RecalculateChecksum()

	return pkt
}

// buildIPv6Raw constructs a complete IPv6 packet with an arbitrary next-header
// payload (used for ICMPv6).
func (e *nat66Engine) buildIPv6Raw(srcIP net.IP, dstIP net.IP, nextHeader byte, payload []byte) *vpn.Packet {
	totalLen := ipv6.HeaderLen + len(payload)
	if totalLen > vpn.MaxPacketBodySize {
		e.logger.Warnf("NAT66 return packet too large (%d bytes)", totalLen)
		return nil
	}

	pkt := e.device.GetTempPacket()
	const tunPacketOffset = 14
	ip := pkt.Buffer[tunPacketOffset : tunPacketOffset+totalLen]

	// IPv6 header.
	ip[0] = 0x60
	ip[1] = 0
	ip[2] = 0
	ip[3] = 0
	binary.BigEndian.PutUint16(ip[4:6], uint16(len(payload)))
	ip[6] = nextHeader
	ip[7] = 64
	copy(ip[8:24], srcIP.To16())
	copy(ip[24:40], dstIP.To16())

	// Payload.
	copy(ip[ipv6.HeaderLen:], payload)

	pkt.Packet = ip
	pkt.IsIPv6 = true
	pkt.IPProtocol = nextHeader
	pkt.Src = ip[8:24]
	pkt.Dst = ip[24:40]
	pkt.RecalculateChecksum()

	return pkt
}

func (e *nat66Engine) cleanupLoop() {
	defer e.cleanupW.Done()
	ticker := time.NewTicker(nat66CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-e.done:
			return
		case <-ticker.C:
			now := time.Now().UnixNano()
			timeout := nat66UDPTimeout.Nanoseconds()

			e.udpMu.Lock()
			for key, entry := range e.udpEntries {
				if now-entry.lastUsed.Load() > timeout {
					_ = entry.conn.Close()
					delete(e.udpEntries, key)
				}
			}
			e.udpMu.Unlock()
		}
	}
}

func (e *nat66Engine) Close() error {
	if !e.closed.CompareAndSwap(false, true) {
		return nil
	}
	close(e.done)

	// Close all UDP connections to unblock readers.
	e.udpMu.Lock()
	for _, entry := range e.udpEntries {
		_ = entry.conn.Close()
	}
	e.udpMu.Unlock()

	e.cleanupW.Wait()
	return nil
}
