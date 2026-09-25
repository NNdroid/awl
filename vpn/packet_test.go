package vpn

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TODO: also test tcp packets, ip packets with variable header size
func TestPacket_RecalculateChecksum(t *testing.T) {
	a := require.New(t)
	packet, rawData := testUDPPacket()
	packet.RecalculateChecksum()
	a.Equal(rawData, packet.Packet)
}

func TestPacket_RecalculateChecksum_IPv6(t *testing.T) {
	a := require.New(t)
	packet, rawData := testUDPPacketIPv6()
	// testUDPPacketIPv6 has 0000 for checksum, calling RecalculateChecksum will update it
	packet.RecalculateChecksum()
	// Just verify it doesn't crash and actually modifies the checksum if it was 0000
	a.NotEqual(rawData, packet.Packet)

	// Test idempotency
	firstRecalculate := append([]byte(nil), packet.Packet...)
	packet.RecalculateChecksum()
	a.Equal(firstRecalculate, packet.Packet)
}

func TestPacket_RecalculateChecksum_IPv6DestinationOptions(t *testing.T) {
	src := net.ParseIP("fd00:66::1").To16()
	dst := net.ParseIP("2001:4860:4860::8888").To16()
	newSrc := net.ParseIP("fd00:66::2").To16()
	require.NotNil(t, src)
	require.NotNil(t, dst)
	require.NotNil(t, newSrc)

	udp := make([]byte, 8+12)
	binary.BigEndian.PutUint16(udp[0:], 1234)
	binary.BigEndian.PutUint16(udp[2:], 443)
	binary.BigEndian.PutUint16(udp[4:], uint16(len(udp)))
	copy(udp[8:], []byte("hello-ipv6!!"))

	raw := make([]byte, 40+8+len(udp))
	raw[0] = 0x60
	binary.BigEndian.PutUint16(raw[4:], uint16(len(raw)-40))
	raw[6] = ipv6NextDestOpts
	raw[7] = 64
	copy(raw[8:24], src)
	copy(raw[24:40], dst)
	raw[40] = IPProtocolUDP // Destination Options -> UDP
	raw[41] = 0             // 8-byte extension header
	copy(raw[48:], udp)

	p := new(Packet)
	_, err := p.ReadFrom(bytes.NewReader(raw))
	require.NoError(t, err)
	require.True(t, p.Parse())

	p.RecalculateChecksum()
	require.NotZero(t, binary.BigEndian.Uint16(p.Packet[54:56]))
	require.Equal(t, uint16(0),
		checksumIPv6TCPUDP(p.Packet[48:], IPProtocolUDP, p.Src, p.Dst),
		"checksum must validate with a Destination Options header present")

	copy(p.Src, newSrc)
	p.RecalculateChecksum()
	require.Equal(t, uint16(0),
		checksumIPv6TCPUDP(p.Packet[48:], IPProtocolUDP, p.Src, p.Dst),
		"checksum must remain valid after gateway source rewrite")
}

func TestPacket_RecalculateChecksum_IPv6FirstFragmentUsesIncrementalAdjustment(t *testing.T) {
	oldSrc := net.ParseIP("fd00:66::1").To16()
	newSrc := net.ParseIP("fd00:66::2").To16()
	dst := net.ParseIP("2001:4860:4860::8888").To16()
	require.NotNil(t, oldSrc)
	require.NotNil(t, newSrc)
	require.NotNil(t, dst)

	// Build the complete UDP datagram first so its checksum represents the
	// reassembled packet, then place only its first bytes in fragment #0.
	fullUDP := make([]byte, 8+24)
	binary.BigEndian.PutUint16(fullUDP[0:], 1234)
	binary.BigEndian.PutUint16(fullUDP[2:], 443)
	binary.BigEndian.PutUint16(fullUDP[4:], uint16(len(fullUDP)))
	copy(fullUDP[8:], []byte("fragmented-ipv6-payload!"))
	oldChecksum := checksumIPv6TCPUDP(fullUDP, IPProtocolUDP, oldSrc, dst)
	if oldChecksum == 0 {
		oldChecksum = 0xffff
	}
	binary.BigEndian.PutUint16(fullUDP[6:], oldChecksum)

	expectedUDP := append([]byte(nil), fullUDP...)
	binary.BigEndian.PutUint16(expectedUDP[6:], 0)
	expectedChecksum := checksumIPv6TCPUDP(expectedUDP, IPProtocolUDP, newSrc, dst)
	if expectedChecksum == 0 {
		expectedChecksum = 0xffff
	}

	const firstFragmentBytes = 16
	raw := make([]byte, 40+8+firstFragmentBytes)
	raw[0] = 0x60
	binary.BigEndian.PutUint16(raw[4:], uint16(len(raw)-40))
	raw[6] = ipv6NextFragment
	raw[7] = 64
	copy(raw[8:24], oldSrc)
	copy(raw[24:40], dst)
	raw[40] = IPProtocolUDP
	raw[41] = 0
	// Fragment offset = 0, M = 1.
	binary.BigEndian.PutUint16(raw[42:], 1)
	binary.BigEndian.PutUint32(raw[44:], 0x12345678)
	copy(raw[48:], fullUDP[:firstFragmentBytes])

	p := new(Packet)
	_, err := p.ReadFrom(bytes.NewReader(raw))
	require.NoError(t, err)
	require.True(t, p.Parse())

	copy(p.Src, newSrc)
	p.RecalculateChecksum()
	require.Equal(t, expectedChecksum, binary.BigEndian.Uint16(p.Packet[54:56]),
		"first-fragment checksum must be adjusted for the IPv6 pseudo-header address rewrite")

	first := append([]byte(nil), p.Packet...)
	p.RecalculateChecksum()
	require.Equal(t, first, p.Packet, "incremental fragment adjustment must be idempotent")
}

func TestIPv6UpperLayerNonFirstFragment(t *testing.T) {
	raw := make([]byte, 40+8+8)
	raw[0] = 0x60
	binary.BigEndian.PutUint16(raw[4:], uint16(len(raw)-40))
	raw[6] = ipv6NextFragment
	raw[40] = IPProtocolUDP
	// Fragment offset = 1 (8 bytes), M = 1.
	binary.BigEndian.PutUint16(raw[42:], (1<<3)|1)

	proto, off, fragmented, first, ok := ipv6UpperLayer(raw)
	require.True(t, ok)
	require.Equal(t, byte(IPProtocolUDP), proto)
	require.Equal(t, 48, off)
	require.True(t, fragmented)
	require.False(t, first)
}

// TODO: bench with bigger packet
func BenchmarkPacket_RecalculateChecksum(b *testing.B) {
	packet, _ := testUDPPacket()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		packet.RecalculateChecksum()
	}
}

func BenchmarkPacket_PoolCopyToClear(b *testing.B) {
	packet, _ := testUDPPacket()

	packetsPool := sync.Pool{
		New: func() interface{} {
			return new(Packet)
		}}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		copyPacket := packetsPool.Get().(*Packet)
		packet.CopyTo(copyPacket)

		copyPacket.clear()
		packetsPool.Put(copyPacket)
	}
}

// a peer-controlled IPv4 packet must never be able to crash the process
// through Parse/RecalculateChecksum slicing past the packet bounds.
func TestPacket_Parse_RejectsMalformedIPv4(t *testing.T) {
	newRawIPv4 := func(size int, ihlWords byte, protocol byte) []byte {
		raw := make([]byte, size)
		raw[0] = 0x40 | (ihlWords & 0x0f) // version 4 + IHL
		if len(raw) > 9 {
			raw[9] = protocol
		}
		return raw
	}

	cases := []struct {
		name string
		raw  []byte
	}{
		{"ihl larger than packet", newRawIPv4(20, 15, 0)}, // ipHeaderLen is 60 > 20
		{"ihl below minimum", newRawIPv4(20, 4, 0)},       // ipHeaderLen is 16 < 20
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := new(Packet)
			_, _ = p.ReadFrom(bytes.NewReader(tc.raw))
			require.False(t, p.Parse(), "malformed packet must be rejected by Parse")
		})
	}
}

func TestPacket_Parse_RejectsMalformedIPv6(t *testing.T) {
	newRawIPv6 := func(size int, nextHeader byte) []byte {
		raw := make([]byte, size)
		raw[0] = 0x60 // version 6
		if len(raw) > 6 {
			raw[6] = nextHeader
		}
		return raw
	}

	cases := []struct {
		name string
		raw  []byte
	}{
		{"length less than ipv6 header", newRawIPv6(20, 17)}, // ipv6 header is 40
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := new(Packet)
			_, _ = p.ReadFrom(bytes.NewReader(tc.raw))
			require.False(t, p.Parse(), "malformed IPv6 packet must be rejected by Parse")
		})
	}
}

// defense in depth: RecalculateChecksum must be panic-safe on malformed or
// truncated packets, including when called without a prior successful Parse.
func TestPacket_RecalculateChecksum_MalformedNoPanic(t *testing.T) {
	build := func(size int, ihlWords, protocol byte) *Packet {
		raw := make([]byte, size)
		raw[0] = 0x40 | (ihlWords & 0x0f)
		if len(raw) > 9 {
			raw[9] = protocol
		}
		p := new(Packet)
		_, _ = p.ReadFrom(bytes.NewReader(raw))
		// Src/Dst are populated by Parse; the guards must hold even when they are
		// nil (RecalculateChecksum called directly).
		return p
	}

	cases := []struct {
		name            string
		size            int
		ihlWords, proto byte
	}{
		{"ihl past packet, tcp", 20, 15, IPProtocolTCP},
		{"ihl past packet, udp", 20, 15, IPProtocolUDP},
		{"valid ihl, tcp header truncated", 20, 5, IPProtocolTCP},
		{"valid ihl, udp header truncated", 24, 5, IPProtocolUDP},
		{"valid ihl, non-transport proto", 20, 5, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := build(tc.size, tc.ihlWords, tc.proto)
			require.NotPanics(t, func() { p.RecalculateChecksum() })
		})
	}
}

// C2: an oversized tunnel packet must return an error rather than spinning
// forever on zero-length reads into the full buffer. Reproduces the production
// path (io.LimitedReader wrapping the peer stream).
func TestPacket_ReadFrom_RejectsOversized(t *testing.T) {
	body := bytes.Repeat([]byte{0xab}, MaxPacketBodySize*2)
	lr := &io.LimitedReader{R: bytes.NewReader(body), N: int64(len(body))}
	p := new(Packet)

	done := make(chan error, 1)
	go func() {
		_, err := p.ReadFrom(lr)
		done <- err
	}()

	select {
	case err := <-done:
		require.Error(t, err)
		require.Contains(t, err.Error(), "exceeds max")
	case <-time.After(2 * time.Second):
		t.Fatal("ReadFrom looped forever on oversized packet")
	}
}

// C2 boundary: the largest body that still leaves the buffer with room (i.e.
// does not fill it) must be read successfully.
func TestPacket_ReadFrom_AcceptsMaxSize(t *testing.T) {
	size := MaxPacketBodySize - 1
	body := bytes.Repeat([]byte{0xab}, size)
	lr := &io.LimitedReader{R: bytes.NewReader(body), N: int64(len(body))}
	p := new(Packet)

	n, err := p.ReadFrom(lr)
	require.NoError(t, err)
	require.Equal(t, int64(size), n)
	require.Len(t, p.Packet, size)
}

// H11: CopyTo must re-point Src/Dst onto the copy's own buffer, otherwise they
// dangle into the original's buffer and read garbage once it is reused.
func TestPacket_CopyTo_SrcDstAliasCopyBuffer(t *testing.T) {
	a := require.New(t)
	orig, _ := testUDPPacket()
	a.NotNil(orig.Src)
	a.NotNil(orig.Dst)

	wantSrc := append(net.IP(nil), orig.Src...)
	wantDst := append(net.IP(nil), orig.Dst...)

	cp := new(Packet)
	orig.CopyTo(cp)

	// Simulate the original returning to the pool and its buffer being reused.
	for i := range orig.Buffer {
		orig.Buffer[i] = 0xff
	}

	a.Equal(wantSrc, cp.Src, "copy Src must survive original buffer reuse")
	a.Equal(wantDst, cp.Dst, "copy Dst must survive original buffer reuse")
	// Recalculating on the copy must still yield the correct checksum.
	a.NotPanics(func() { cp.RecalculateChecksum() })
}

func testUDPPacket() (*Packet, []byte) {
	data, err := hex.DecodeString("4500002828f540004011fd490a4200010a420002a9d0238200148bfd68656c6c6f20776f726c6421")
	if err != nil {
		panic(err)
	}

	packet := new(Packet)
	_, _ = packet.ReadFrom(bytes.NewReader(data))
	packet.Parse()

	return packet, data
}

func testUDPPacketIPv6() (*Packet, []byte) {
	data, err := hex.DecodeString("6000000000141140fd000000000000000000000000000001fd00000000000000000000000000000204d2162e0014000068656c6c6f20776f726c6421")
	if err != nil {
		panic(err)
	}

	packet := new(Packet)
	_, _ = packet.ReadFrom(bytes.NewReader(data))
	packet.Parse()

	return packet, data
}

func TestGetIPv4BroadcastAddress(t *testing.T) {
	tests := []struct {
		name  string
		ipNet *net.IPNet
		want  net.IP
	}{
		{
			name:  "awl-default",
			ipNet: getIPNet("10.66.0.1/16"),
			want:  net.IPv4(10, 66, 255, 255).To4(),
		},
		{
			name:  "local-network",
			ipNet: getIPNet("192.168.1.19/24"),
			want:  net.IPv4(192, 168, 1, 255).To4(),
		},
		{
			name:  "docker-network",
			ipNet: getIPNet("172.17.0.1/16"),
			want:  net.IPv4(172, 17, 255, 255).To4(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetIPv4BroadcastAddress(tt.ipNet); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetIPv4BroadcastAddress() = %v, want %v", got, tt.want)
			}
		})
	}
}

func getIPNet(s string) *net.IPNet {
	_, ipNet, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return ipNet
}
