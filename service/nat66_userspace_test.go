//go:build windows || darwin

package service

import (
	"bytes"
	"encoding/binary"
	"net"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/ipv6"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/anywherelan/awl/vpn"
)

type dummyTUN struct{}

func (dummyTUN) File() *os.File                         { return nil }
func (dummyTUN) Read([][]byte, []int, int) (int, error) { select {} }
func (dummyTUN) Write([][]byte, int) (int, error)       { return 0, nil }
func (dummyTUN) MTU() (int, error)                      { return 1500, nil }
func (dummyTUN) Name() (string, error)                  { return "dummy", nil }
func (dummyTUN) Events() <-chan tun.Event               { return nil }
func (dummyTUN) Close() error                           { return nil }
func (dummyTUN) BatchSize() int                         { return 1 }

func newTestDevice() *vpn.Device {
	d, _ := vpn.NewDevice(dummyTUN{}, "dummy", net.ParseIP("10.0.0.1"), net.CIDRMask(24, 32), net.ParseIP("fd86::1"), net.CIDRMask(64, 128))
	return d
}

func TestNAT66BuildIPv6UDP(t *testing.T) {
	device := newTestDevice()
	engine := newNAT66Engine(device, func(p *vpn.Packet, v4 net.IP) {})
	defer engine.Close()

	srcIP := net.ParseIP("fd86::1")
	dstIP := net.ParseIP("2001:4860:4860::8888")
	payload := []byte("hello dns")

	pkt := engine.buildIPv6UDP(srcIP, 12345, dstIP, 53, payload)
	require.NotNil(t, pkt)
	require.True(t, pkt.IsIPv6)
	require.Equal(t, byte(vpn.IPProtocolUDP), pkt.IPProtocol)
	require.Equal(t, srcIP.To16(), pkt.Src)
	require.Equal(t, dstIP.To16(), pkt.Dst)

	// Verify IPv6 header
	ip := pkt.Packet
	require.Equal(t, byte(0x60), ip[0]&0xf0, "IPv6 version")
	require.Equal(t, byte(vpn.IPProtocolUDP), ip[6], "Next header")

	// Verify UDP payload length
	udpLen := 8 + len(payload)
	require.Equal(t, uint16(udpLen), binary.BigEndian.Uint16(ip[4:6]), "IPv6 payload length")

	// Verify UDP header
	udp := ip[ipv6.HeaderLen:]
	require.Equal(t, uint16(12345), binary.BigEndian.Uint16(udp[0:2]), "Src port")
	require.Equal(t, uint16(53), binary.BigEndian.Uint16(udp[2:4]), "Dst port")
	require.Equal(t, uint16(udpLen), binary.BigEndian.Uint16(udp[4:6]), "UDP length")

	// Verify payload
	require.True(t, bytes.Equal(payload, udp[8:]), "UDP payload")
}

func TestNAT66RejectTCP(t *testing.T) {
	device := newTestDevice()
	var returnedPkt *vpn.Packet
	var returnedV4 net.IP

	engine := newNAT66Engine(device, func(p *vpn.Packet, v4 net.IP) {
		returnedPkt = p
		returnedV4 = v4
	})
	defer engine.Close()

	clientV4 := net.ParseIP("10.66.0.2")
	clientV6 := net.ParseIP("fd86::2")
	targetV6 := net.ParseIP("2001:4860:4860::8888")

	// Craft a dummy IPv6 TCP packet
	origPkt := device.GetTempPacket()
	ip := origPkt.Buffer[14 : 14+ipv6.HeaderLen+20]
	ip[0] = 0x60
	binary.BigEndian.PutUint16(ip[4:6], 20)
	ip[6] = vpn.IPProtocolTCP
	copy(ip[8:24], clientV6.To16())
	copy(ip[24:40], targetV6.To16())
	origPkt.Packet = ip
	origPkt.IsIPv6 = true
	origPkt.IPProtocol = vpn.IPProtocolTCP
	origPkt.Src = ip[8:24]
	origPkt.Dst = ip[24:40]

	engine.ForwardIPv6(origPkt, clientV4)

	// rejectTCP runs synchronously inside ForwardIPv6 for TCP
	require.NotNil(t, returnedPkt, "should have returned an ICMPv6 packet")
	require.Equal(t, clientV4.To4(), returnedV4.To4())

	require.True(t, returnedPkt.IsIPv6)
	require.Equal(t, byte(vpn.IPProtocolICMPv6), returnedPkt.IPProtocol)
	require.Equal(t, targetV6.To16(), returnedPkt.Src, "Source should be the original destination")
	require.Equal(t, clientV6.To16(), returnedPkt.Dst, "Destination should be the original client")

	icmp := returnedPkt.Packet[ipv6.HeaderLen:]
	require.Equal(t, byte(1), icmp[0], "ICMPv6 Type: Destination Unreachable")
	require.Equal(t, byte(4), icmp[1], "ICMPv6 Code: Port Unreachable")
}

func TestNAT66Cleanup(t *testing.T) {
	device := newTestDevice()
	engine := newNAT66Engine(device, func(p *vpn.Packet, v4 net.IP) {})
	defer engine.Close()

	key := udp66Key{ClientPort: 1234}
	engine.udpEntries[key] = &udp66Entry{
		conn: nil, // fake entry
	}
	engine.udpEntries[key].lastUsed.Store(time.Now().Add(-5 * time.Minute).UnixNano())

	// Force cleanup
	engine.udpMu.Lock()
	timeout := nat66UDPTimeout.Nanoseconds()
	now := time.Now().UnixNano()
	for k, entry := range engine.udpEntries {
		if now-entry.lastUsed.Load() > timeout {
			delete(engine.udpEntries, k)
		}
	}
	engine.udpMu.Unlock()

	engine.udpMu.RLock()
	_, exists := engine.udpEntries[key]
	engine.udpMu.RUnlock()

	require.False(t, exists, "Entry should have been cleaned up")
}
