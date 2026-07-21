package service

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPeerIPv6FromIPv4(t *testing.T) {
	tests := []struct {
		name       string
		peerIPv4   string
		awlSubnet4 string
		awlSubnet6 string
		expected   string
	}{
		{
			name:       "valid conversion /16 and /112",
			peerIPv4:   "10.66.0.5",
			awlSubnet4: "10.66.0.0/16",
			awlSubnet6: "fd00:66::/112",
			expected:   "fd00:66::5",
		},
		{
			name:       "valid conversion /16 and /48",
			peerIPv4:   "10.66.0.5",
			awlSubnet4: "10.66.0.0/16",
			awlSubnet6: "fd00:66:0::/48",
			expected:   "fd00:66:0::5",
		},
		{
			name:       "valid conversion with larger IPv4 offset",
			peerIPv4:   "10.66.255.5",
			awlSubnet4: "10.66.0.0/16",
			awlSubnet6: "fd00:66:0::/48",
			expected:   "fd00:66:0::ff05",
		},
		{
			name:       "out of bounds IPv4",
			peerIPv4:   "10.67.0.5",
			awlSubnet4: "10.66.0.0/16",
			awlSubnet6: "fd00:66:0::/48",
			expected:   "", // expected nil
		},
		{
			name:       "capacity mismatch v4 host bits > v6 host bits",
			peerIPv4:   "10.66.0.5",
			awlSubnet4: "10.66.0.0/16", // 16 host bits
			awlSubnet6: "fd00:66::/120", // 8 host bits
			expected:   "", // expected nil
		},
		{
			name:       "invalid mask lengths (v4)",
			peerIPv4:   "10.66.0.5",
			awlSubnet4: "10.66.0.0/16",
			awlSubnet6: "fd00:66::/112",
			expected:   "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			peerIP := net.ParseIP(tc.peerIPv4)
			var sub4, sub6 *net.IPNet

			if tc.awlSubnet4 != "" {
				_, sub4, _ = net.ParseCIDR(tc.awlSubnet4)
				if tc.name == "invalid mask lengths (v4)" {
					sub4.Mask = net.CIDRMask(16, 128)
				}
			}
			if tc.awlSubnet6 != "" {
				_, sub6, _ = net.ParseCIDR(tc.awlSubnet6)
			}

			result := peerIPv6FromIPv4(peerIP, sub4, sub6)

			if tc.expected == "" {
				assert.Nil(t, result)
			} else {
				assert.NotNil(t, result)
				assert.Equal(t, net.ParseIP(tc.expected).To16(), result)
			}
		})
	}

	t.Run("nil inputs", func(t *testing.T) {
		assert.Nil(t, peerIPv6FromIPv4(nil, nil, nil))

		_, sub4, _ := net.ParseCIDR("10.66.0.0/16")
		_, sub6, _ := net.ParseCIDR("fd00:66:0::/48")
		assert.Nil(t, peerIPv6FromIPv4(net.ParseIP("10.66.0.5"), nil, sub6))
		assert.Nil(t, peerIPv6FromIPv4(net.ParseIP("10.66.0.5"), sub4, nil))
	})
}
