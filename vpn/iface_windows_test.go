//go:build windows

package vpn

import (
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWindowsTUNPrefixesDualStack(t *testing.T) {
	got, err := windowsTUNPrefixes(
		net.ParseIP("10.66.0.23"),
		net.CIDRMask(16, 32),
		net.ParseIP("fd00:66:0::23"),
		net.CIDRMask(48, 128),
	)
	require.NoError(t, err)
	require.Equal(t, []netip.Prefix{
		netip.MustParsePrefix("10.66.0.23/16"),
		netip.MustParsePrefix("fd00:66:0::23/48"),
	}, got)
}

func TestWindowsTUNPrefixesIPv4Only(t *testing.T) {
	got, err := windowsTUNPrefixes(
		net.ParseIP("10.66.0.23"),
		net.CIDRMask(16, 32),
		nil,
		nil,
	)
	require.NoError(t, err)
	require.Equal(t, []netip.Prefix{netip.MustParsePrefix("10.66.0.23/16")}, got)
}

func TestWindowsTUNPrefixesRejectsInvalidFamilies(t *testing.T) {
	_, err := windowsTUNPrefixes(net.ParseIP("fd00::1"), net.CIDRMask(64, 128), nil, nil)
	require.Error(t, err)

	_, err = windowsTUNPrefixes(
		net.ParseIP("10.66.0.23"),
		net.CIDRMask(16, 32),
		net.ParseIP("192.0.2.1"),
		net.CIDRMask(48, 128),
	)
	require.Error(t, err)
}
