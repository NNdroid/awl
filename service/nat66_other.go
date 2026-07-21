//go:build !windows && !darwin

package service

import (
	"net"

	"github.com/anywherelan/awl/vpn"
)

func newNAT66Engine(_ *vpn.Device, _ nat66ReturnFunc) *nat66Engine {
	return nil
}

// nat66Engine is a no-op stub on non-Windows platforms where kernel-level
// IPv6 NAT (ip6tables MASQUERADE) handles gateway forwarding natively.
type nat66Engine struct{}

func (e *nat66Engine) ForwardIPv6(_ *vpn.Packet, _ net.IP) {}
func (e *nat66Engine) Close() error                        { return nil }
