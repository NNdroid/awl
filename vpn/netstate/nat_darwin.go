//go:build darwin

package netstate

import (
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strings"
)

// darwinNATState holds everything needed to tear down server-side NAT.
type darwinNATState struct {
	uplink          string // e.g. "en0"
	awlSubnet       string // e.g. "10.66.0.0/24"
	tunIfName       string // e.g. "utun5"
	origIPv4Forward string // "0" or "1" — restored on teardown only if we changed it
	origIPv6Forward string // "0" or "1" — same semantics as IPv4
}

// setupDarwinNAT enables server-side IPv4 NAT via pf.
//
// IPv4 flow: client packet arrives on tunIfName → kernel forwards to uplink →
// pf MASQUERADE rewrites src to the uplink address.
//
// IPv6 flow: handled entirely by the userspace nat66Engine (service layer),
// not here. We only enable IPv6 forwarding via sysctl so the kernel will
// forward packets between tunIfName and the uplink once the nat66Engine has
// rewritten addresses.
func (m *Manager) setupDarwinNAT(awlSubnet, tunIfName string) (*darwinNATState, error) {
	uplink, err := detectUplinkIfName()
	if err != nil {
		return nil, fmt.Errorf("detect uplink interface: %w", err)
	}

	state := &darwinNATState{
		uplink:    uplink,
		awlSubnet: awlSubnet,
		tunIfName: tunIfName,
	}

	// Enable IPv4 forwarding, saving the original value for restoration.
	if v, err := sysctlGet("net.inet.ip.forwarding"); err == nil {
		state.origIPv4Forward = v
		if v == "0" {
			if err := sysctlSet("net.inet.ip.forwarding", "1"); err != nil {
				return nil, fmt.Errorf("enable IPv4 forwarding: %w", err)
			}
		}
	}

	// Enable IPv6 forwarding (used by the nat66Engine return path).
	if v, err := sysctlGet("net.inet6.ip6.forwarding"); err == nil {
		state.origIPv6Forward = v
		if v == "0" {
			if err := sysctlSet("net.inet6.ip6.forwarding", "1"); err != nil {
				// Not fatal — IPv4 gateway still works.
				logger.Warnf("darwin: enable IPv6 forwarding: %v (IPv4 gateway still active)", err)
				state.origIPv6Forward = "" // don't restore what we didn't set
			}
		}
	}

	// Ensure pf is running and our anchor hierarchy is referenced.
	if err := m.ensurePFSetup(); err != nil {
		_ = m.teardownDarwinNAT(state)
		return nil, fmt.Errorf("pf setup: %w", err)
	}

	// Build IPv4 NAT rule: masquerade awlSubnet traffic going out via uplink.
	// Private-subnet drop rules are enforced by the AWL-FORWARD chain
	// equivalent — we replicate them here via pf's "no nat" directives so
	// the exit node cannot reach LAN or CGNAT targets.
	var natRules strings.Builder
	// Exclude private destinations from NAT (they would be dropped anyway,
	// but explicit "no nat" keeps the rule table readable and prevents
	// accidental LAN exposure if the user's kernel forwards those packets).
	for _, priv := range privateSubnets {
		fmt.Fprintf(&natRules, "no nat on %s from %s to %s\n", uplink, awlSubnet, priv)
	}
	fmt.Fprintf(&natRules, "nat on %s from %s to any -> (%s)\n", uplink, awlSubnet, uplink)

	if err := runPfctlWithStdin(natRules.String(), "-a", awlPFAnchor+"/nat", "-f", "-"); err != nil {
		m.releasePFSetup()
		_ = m.teardownDarwinNAT(state)
		return nil, fmt.Errorf("load pf NAT rules: %w", err)
	}

	logger.Infof("darwin: pf NAT configured for %s via %s on %s", awlSubnet, uplink, tunIfName)
	return state, nil
}

// teardownDarwinNAT reverses setupDarwinNAT. Safe to call on partially-set-up
// state.
func (m *Manager) teardownDarwinNAT(state *darwinNATState) error {
	if state == nil {
		return nil
	}
	var errs []error

	// Flush our NAT sub-anchor. Errors here are logged, not fatal — the
	// anchor disappears from the main ruleset when releasePFSetup restores
	// the original rules below.
	if err := runPfctlCmd("-a", awlPFAnchor+"/nat", "-F", "all"); err != nil {
		logger.Warnf("darwin: flush pf NAT anchor: %v", err)
	}
	m.releasePFSetup()

	// Restore IPv4 forwarding only if we turned it on.
	if state.origIPv4Forward == "0" {
		if err := sysctlSet("net.inet.ip.forwarding", "0"); err != nil {
			errs = append(errs, fmt.Errorf("restore IPv4 forwarding: %w", err))
		}
	}

	// Restore IPv6 forwarding only if we turned it on.
	if state.origIPv6Forward == "0" {
		if err := sysctlSet("net.inet6.ip6.forwarding", "0"); err != nil {
			errs = append(errs, fmt.Errorf("restore IPv6 forwarding: %w", err))
		}
	}

	return errors.Join(errs...)
}

// detectUplinkIfName returns the name of the interface currently carrying the
// IPv4 default route (e.g. "en0").
func detectUplinkIfName() (string, error) {
	out, err := exec.Command("route", "-n", "get", "default").Output()
	if err != nil {
		return "", fmt.Errorf("route get default: %w", err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "interface:") {
			name := strings.TrimSpace(strings.TrimPrefix(line, "interface:"))
			if name != "" {
				return name, nil
			}
		}
	}
	return "", fmt.Errorf("no default-route interface found in route output")
}

// detectUplinkInterface returns the name, IPv4 gateway address, and
// net.Interface index of the interface carrying the default IPv4 route.
func detectUplinkInterface() (ifName, gwIP string, ifIdx int, err error) {
	out, cmdErr := exec.Command("route", "-n", "get", "default").Output()
	if cmdErr != nil {
		return "", "", 0, fmt.Errorf("route get default: %w", cmdErr)
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "gateway:"):
			gwIP = strings.TrimSpace(strings.TrimPrefix(line, "gateway:"))
		case strings.HasPrefix(line, "interface:"):
			ifName = strings.TrimSpace(strings.TrimPrefix(line, "interface:"))
		}
	}
	if ifName == "" {
		return "", "", 0, fmt.Errorf("no default-route interface found in route output")
	}
	iface, err := net.InterfaceByName(ifName)
	if err != nil {
		return "", "", 0, fmt.Errorf("interface %q: %w", ifName, err)
	}
	return ifName, gwIP, iface.Index, nil
}
