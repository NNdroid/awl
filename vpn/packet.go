package vpn

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.zx2c4.com/wireguard/device"
)

const (
	IPProtocolTCP    = 6
	IPProtocolUDP    = 17
	IPProtocolICMPv6 = 58

	ipv4offsetChecksum = 10

	ipv6NextHopByHop = 0
	ipv6NextRouting  = 43
	ipv6NextFragment = 44
	ipv6NextESP      = 50
	ipv6NextAH       = 51
	ipv6NextNoHeader = 59
	ipv6NextDestOpts = 60
)

type Packet struct {
	Buffer     [maxContentSize]byte
	Packet     []byte
	Src        net.IP
	Dst        net.IP
	IsIPv6     bool
	GatewayDir GatewayDir
	IPProtocol byte

	// IPv6 fragmentation needs incremental pseudo-header checksum adjustment:
	// a first fragment does not contain the whole transport segment, so a full
	// checksum cannot be recomputed after src/dst rewriting. Parse snapshots
	// the pre-rewrite addresses here; arrays copy safely through Packet.CopyTo.
	originalIPv6Src   [net.IPv6len]byte
	originalIPv6Dst   [net.IPv6len]byte
	originalIPv6Valid bool
}

// GatewayDir tags a tunnel packet's intent with respect to VPN gateway mode.
type GatewayDir uint8

const (
	// GatewayDirNone is a regular awl peer-to-peer packet. Receiver applies the
	// standard full src/dst rewrite.
	GatewayDirNone GatewayDir = iota
	// GatewayDirForward is sent client → server: the sender asks the receiver,
	// who must be acting as a VPN gateway server for the sender, to forward
	// this packet to the internet via NAT. Receiver rewrites only src.
	GatewayDirForward
	// GatewayDirReturn is sent server → client: the sender (the gateway server)
	// is delivering a NAT-returned packet from the internet back to the client.
	// Receiver rewrites only dst.
	GatewayDirReturn
)

// Buf returns the slice of data.Buffer that includes the TUN header offset and
// the parsed packet body, ready to be appended into a bufs slice for tun.Write.
func (data *Packet) Buf() []byte {
	return data.Buffer[:tunPacketOffset+len(data.Packet)]
}

func (data *Packet) clear() {
	data.Packet = nil
	data.Src = nil
	data.Dst = nil
	data.IsIPv6 = false
	data.IPProtocol = 0
	data.GatewayDir = GatewayDirNone
	data.originalIPv6Valid = false
}

func (data *Packet) CopyTo(copyPacket *Packet) {
	*copyPacket = *data
	// Buffer is an array copied by value above, but Packet/Src/Dst are slice
	// headers still aliasing data.Buffer. Re-derive them as sub-slices of the
	// copy's own buffer.
	copyPacket.Packet = copyPacket.Buffer[tunPacketOffset : len(data.Packet)+tunPacketOffset]
	if data.Src != nil {
		copyPacket.setAddrs()
	}
}

func (data *Packet) ReadFrom(stream io.Reader) (int64, error) {
	totalRead := tunPacketOffset
	for {
		n, err := stream.Read(data.Buffer[totalRead:])
		totalRead += n
		if err == io.EOF {
			data.Packet = data.Buffer[tunPacketOffset:totalRead]
			return int64(totalRead - tunPacketOffset), nil
		} else if err != nil {
			return int64(totalRead - tunPacketOffset), err
		}
		// The buffer is sized with slack above the MTU (maxContentSize), so a
		// valid single-packet body never fills it. A full buffer means an
		// oversized frame; reject it instead of reading into the empty tail
		// (which would spin on (0, nil) reads).
		if totalRead == len(data.Buffer) {
			return int64(totalRead - tunPacketOffset), fmt.Errorf("packet body exceeds max size %d bytes", MaxPacketBodySize)
		}
	}
}

func (data *Packet) Parse() bool {
	data.originalIPv6Valid = false
	if len(data.Packet) == 0 {
		return false
	}

	packet := data.Packet
	switch version := packet[0] >> 4; version {
	case ipv4.Version:
		if len(packet) < ipv4.HeaderLen {
			return false
		}
		// Validate the header length against the actual packet so downstream
		// slicing (RecalculateChecksum) can't run past the packet and panic.
		// Transport-length is not enforced here (it would drop legit non-first IP
		// fragments); RecalculateChecksum guards its own transport slicing.
		ipHeaderLen := int(packet[0]&0x0f) << 2
		if ipHeaderLen < ipv4.HeaderLen || ipHeaderLen > len(packet) {
			return false
		}
		data.IPProtocol = packet[9]

		data.IsIPv6 = false
		data.setAddrs()
	case ipv6.Version:
		if len(packet) < ipv6.HeaderLen {
			return false
		}

		data.IsIPv6 = true
		data.setAddrs()
		data.rememberIPv6Addrs()
		// Keep the base-header value for compatibility. RecalculateChecksum
		// walks the extension-header chain to find the real upper layer.
		data.IPProtocol = packet[6]
	default:
		return false
	}

	return true
}

func (data *Packet) RecalculateChecksum() {
	if data.IsIPv6 {
		data.recalculateChecksumIPv6()
		return
	}
	// Guard against malformed lengths so a bad packet can't slice past bounds and
	// panic, even if RecalculateChecksum is called without a prior valid Parse.
	ipHeaderLen := int(data.Packet[0]&0x0f) << 2
	if ipHeaderLen < ipv4.HeaderLen || ipHeaderLen > len(data.Packet) {
		return
	}
	copy(data.Packet[ipv4offsetChecksum:], []byte{0, 0})
	ipChecksum := checksumIPv4Header(data.Packet[:ipHeaderLen])
	binary.BigEndian.PutUint16(data.Packet[ipv4offsetChecksum:], ipChecksum)

	switch protocol := data.Packet[9]; protocol {
	case IPProtocolTCP:
		if len(data.Packet) < ipHeaderLen+18 {
			return
		}
		tcpOffsetChecksum := ipHeaderLen + 16
		copy(data.Packet[tcpOffsetChecksum:], []byte{0, 0})
		checksum := checksumIPv4TCPUDP(data.Packet[ipHeaderLen:], uint32(protocol), data.Src, data.Dst)
		binary.BigEndian.PutUint16(data.Packet[tcpOffsetChecksum:], checksum)
	case IPProtocolUDP:
		if len(data.Packet) < ipHeaderLen+8 {
			return
		}
		udpOffsetChecksum := ipHeaderLen + 6
		copy(data.Packet[udpOffsetChecksum:], []byte{0, 0})
		checksum := checksumIPv4TCPUDP(data.Packet[ipHeaderLen:], uint32(protocol), data.Src, data.Dst)
		binary.BigEndian.PutUint16(data.Packet[udpOffsetChecksum:], checksum)
	}
}

// recalculateChecksumIPv6 updates TCP/UDP/ICMPv6 checksums after an IPv6
// src/dst rewrite. It walks the common IPv6 extension headers so full-tunnel
// traffic with Hop-by-Hop, Routing or Destination Options headers is handled
// correctly.
//
// Fragmented traffic needs special treatment: only the first fragment carries
// the transport checksum, while no individual fragment contains the complete
// upper-layer payload. For that first fragment we therefore adjust the
// existing checksum incrementally for the pseudo-header address delta (RFC
// 1624) instead of trying to recompute it from incomplete data. Non-first
// fragments contain no checksum field and need no transport-layer mutation.
func (data *Packet) recalculateChecksumIPv6() {
	if len(data.Packet) < ipv6.HeaderLen || len(data.Src) != net.IPv6len || len(data.Dst) != net.IPv6len {
		return
	}

	protocol, transportOffset, fragmented, firstFragment, ok := ipv6UpperLayer(data.Packet)
	if !ok {
		return
	}
	data.IPProtocol = protocol

	if fragmented {
		if !firstFragment || !data.originalIPv6Valid {
			data.rememberIPv6Addrs()
			return
		}
		transport := data.Packet[transportOffset:]
		var checksumOffset int
		switch protocol {
		case IPProtocolTCP:
			checksumOffset = 16
		case IPProtocolUDP:
			checksumOffset = 6
		case IPProtocolICMPv6:
			checksumOffset = 2
		default:
			data.rememberIPv6Addrs()
			return
		}
		if len(transport) < checksumOffset+2 {
			data.rememberIPv6Addrs()
			return
		}
		oldChecksum := binary.BigEndian.Uint16(transport[checksumOffset:])
		newChecksum := adjustIPv6PseudoHeaderChecksum(
			oldChecksum,
			data.originalIPv6Src[:],
			data.originalIPv6Dst[:],
			data.Src,
			data.Dst,
		)
		// An IPv6 UDP checksum may not be transmitted as zero.
		if protocol == IPProtocolUDP && newChecksum == 0 {
			newChecksum = 0xffff
		}
		binary.BigEndian.PutUint16(transport[checksumOffset:], newChecksum)
		data.rememberIPv6Addrs()
		return
	}

	payload := data.Packet[transportOffset:]
	switch protocol {
	case IPProtocolTCP:
		if len(payload) < 18 {
			return
		}
		copy(payload[16:18], []byte{0, 0})
		checksum := checksumIPv6TCPUDP(payload, uint32(protocol), data.Src, data.Dst)
		binary.BigEndian.PutUint16(payload[16:], checksum)
	case IPProtocolUDP:
		if len(payload) < 8 {
			return
		}
		copy(payload[6:8], []byte{0, 0})
		checksum := checksumIPv6TCPUDP(payload, uint32(protocol), data.Src, data.Dst)
		if checksum == 0 {
			checksum = 0xffff
		}
		binary.BigEndian.PutUint16(payload[6:], checksum)
	case IPProtocolICMPv6:
		if len(payload) < 4 {
			return
		}
		copy(payload[2:4], []byte{0, 0})
		checksum := checksumIPv6TCPUDP(payload, uint32(protocol), data.Src, data.Dst)
		binary.BigEndian.PutUint16(payload[2:], checksum)
	}
	data.rememberIPv6Addrs()
}

// ipv6UpperLayer walks extension headers whose checksum semantics remain
// compatible with the ordinary IPv6 pseudo-header and returns the upper-layer
// protocol and offset. Routing Header is deliberately not handled here: its
// pseudo-header destination can be the final routing destination rather than
// the base IPv6 destination. AH/ESP are also not rewritten because changing
// outer addresses invalidates their authentication and AWL has no IPsec keys
// with which to repair them.
func ipv6UpperLayer(packet []byte) (protocol byte, offset int, fragmented, firstFragment, ok bool) {
	if len(packet) < ipv6.HeaderLen {
		return 0, 0, false, false, false
	}

	next := packet[6]
	offset = ipv6.HeaderLen
	firstFragment = true

	for i := 0; i < 16; i++ {
		switch next {
		case IPProtocolTCP, IPProtocolUDP, IPProtocolICMPv6:
			return next, offset, fragmented, firstFragment, true

		case ipv6NextHopByHop, ipv6NextDestOpts:
			if offset+2 > len(packet) {
				return 0, 0, false, false, false
			}
			headerLen := (int(packet[offset+1]) + 1) * 8
			if headerLen < 8 || offset+headerLen > len(packet) {
				return 0, 0, false, false, false
			}
			next = packet[offset]
			offset += headerLen

		case ipv6NextFragment:
			if offset+8 > len(packet) {
				return 0, 0, false, false, false
			}
			fragField := binary.BigEndian.Uint16(packet[offset+2 : offset+4])
			fragmentOffset := (fragField & 0xfff8) >> 3
			fragmented = true
			firstFragment = fragmentOffset == 0
			next = packet[offset]
			offset += 8
			if !firstFragment {
				// The fragmentable part begins at a non-zero byte offset, so
				// extension/transport headers cannot safely be parsed here.
				return next, offset, true, false, true
			}

		case ipv6NextRouting, ipv6NextESP, ipv6NextAH, ipv6NextNoHeader:
			return next, offset, fragmented, firstFragment, false

		default:
			// Unknown value is an upper-layer protocol AWL does not checksum.
			return next, offset, fragmented, firstFragment, true
		}
	}
	return 0, 0, false, false, false
}

func (data *Packet) rememberIPv6Addrs() {
	if !data.IsIPv6 || len(data.Src) != net.IPv6len || len(data.Dst) != net.IPv6len {
		data.originalIPv6Valid = false
		return
	}
	copy(data.originalIPv6Src[:], data.Src)
	copy(data.originalIPv6Dst[:], data.Dst)
	data.originalIPv6Valid = true
}

// adjustIPv6PseudoHeaderChecksum applies a ones-complement checksum update for
// only the source/destination words in the IPv6 pseudo-header. It is used for
// fragmented packets, where recomputing over the whole upper-layer segment is
// impossible without reassembly.
func adjustIPv6PseudoHeaderChecksum(checksum uint16, oldSrc, oldDst, newSrc, newDst net.IP) uint16 {
	sum := uint32(^checksum)
	adjust := func(oldIP, newIP net.IP) {
		for i := 0; i < net.IPv6len; i += 2 {
			oldWord := binary.BigEndian.Uint16(oldIP[i : i+2])
			newWord := binary.BigEndian.Uint16(newIP[i : i+2])
			sum += uint32(^oldWord) & 0xffff
			sum += uint32(newWord)
			for sum > 0xffff {
				sum = (sum & 0xffff) + (sum >> 16)
			}
		}
	}
	adjust(oldSrc, newSrc)
	adjust(oldDst, newDst)
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func (data *Packet) setAddrs() {
	if data.IsIPv6 {
		data.Src = data.Packet[device.IPv6offsetSrc : device.IPv6offsetSrc+net.IPv6len]
		data.Dst = data.Packet[device.IPv6offsetDst : device.IPv6offsetDst+net.IPv6len]
	} else {
		data.Src = data.Packet[device.IPv4offsetSrc : device.IPv4offsetSrc+net.IPv4len]
		data.Dst = data.Packet[device.IPv4offsetDst : device.IPv4offsetDst+net.IPv4len]
	}
}

func checksumIPv4Header(buf []byte) uint16 {
	var v uint32
	for i := 0; i < len(buf)-1; i += 2 {
		v += uint32(binary.BigEndian.Uint16(buf[i:]))
	}
	if len(buf)%2 == 1 {
		v += uint32(buf[len(buf)-1]) << 8
	}
	for v > 0xffff {
		v = (v >> 16) + (v & 0xffff)
	}

	return ^uint16(v)
}

func checksumIPv4TCPUDP(headerAndPayload []byte, protocol uint32, srcIP net.IP, dstIP net.IP) uint16 {
	var csum uint32
	csum += (uint32(srcIP[0]) + uint32(srcIP[2])) << 8
	csum += uint32(srcIP[1]) + uint32(srcIP[3])
	csum += (uint32(dstIP[0]) + uint32(dstIP[2])) << 8
	csum += uint32(dstIP[1]) + uint32(dstIP[3])

	totalLen := uint32(len(headerAndPayload))

	csum += protocol
	csum += totalLen & 0xffff
	csum += totalLen >> 16

	return tcpipChecksum(headerAndPayload, csum)
}

// checksumIPv6TCPUDP computes an upper-layer checksum using the IPv6
// pseudo-header as defined in RFC 2460 §8.1. The pseudo-header fields are:
//
//	source address       (16 bytes)
//	destination address  (16 bytes)
//	upper-layer length   (4 bytes, big-endian)
//	zero padding         (3 bytes)
//	next header          (1 byte)
//
// headerAndPayload is the transport segment (TCP/UDP header + payload).
// srcIP and dstIP must each be 16 bytes (net.IPv6len).
func checksumIPv6TCPUDP(headerAndPayload []byte, protocol uint32, srcIP net.IP, dstIP net.IP) uint16 {
	var csum uint32
	// Source address
	for i := 0; i < net.IPv6len; i += 2 {
		csum += uint32(srcIP[i])<<8 + uint32(srcIP[i+1])
	}
	// Destination address
	for i := 0; i < net.IPv6len; i += 2 {
		csum += uint32(dstIP[i])<<8 + uint32(dstIP[i+1])
	}
	// Upper-layer packet length (same as transport segment length)
	totalLen := uint32(len(headerAndPayload))
	csum += totalLen >> 16
	csum += totalLen & 0xffff
	// Next Header (protocol)
	csum += protocol

	return tcpipChecksum(headerAndPayload, csum)
}

// Calculate the TCP/IP checksum defined in rfc1071. The passed-in csum is any
// initial checksum data that's already been computed.
// Borrowed from google/gopacket
func tcpipChecksum(data []byte, csum uint32) uint16 {
	// to handle odd lengths, we loop to length - 1, incrementing by 2, then
	// handle the last byte specifically by checking against the original
	// length.
	length := len(data) - 1
	for i := 0; i < length; i += 2 {
		// For our test packet, doing this manually is about 25% faster
		// (740 ns vs. 1000ns) than doing it by calling binary.BigEndian.Uint16.
		csum += uint32(data[i]) << 8
		csum += uint32(data[i+1])
	}
	if len(data)%2 == 1 {
		csum += uint32(data[length]) << 8
	}
	for csum > 0xffff {
		csum = (csum >> 16) + (csum & 0xffff)
	}
	return ^uint16(csum)
}

func GetIPv4BroadcastAddress(ipNet *net.IPNet) net.IP {
	ip := make(net.IP, len(ipNet.IP.To4()))
	// calculate broadcast: network | ^mask
	for i := 0; i < len(ipNet.IP.To4()); i++ {
		ip[i] = ipNet.IP[i] | ^ipNet.Mask[i]
	}

	return ip
}
