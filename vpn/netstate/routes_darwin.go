//go:build darwin

package netstate

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// darwinRouteState holds everything needed to tear down client-side routes
// and the pf kill-switch anchor.
type darwinRouteState struct {
	tunIfName       string
	uplink          string
	ipv4RoutesAdded bool
	ipv6RoutesAdded bool
	pfFilterLoaded  bool
}

// setupClientRoutes installs the gateway client data path on macOS:
//
//  1. Two /1 IPv4 covering routes via the TUN interface (more specific than
//     any /0 default, so they override the existing default without removing
//     it — the original default route remains for the uplink detection at
//     teardown time).
//  2. Two /1 IPv6 covering routes via TUN (best-effort; logged on failure).
//  3. A pf kill-switch anchor (com.awl/filter) that:
//     - passes outbound traffic from the awl process (matched by UID) via uplink
//     - blocks all other outbound traffic via uplink, preventing any leak when
//     traffic somehow bypasses the TUN default routes.
//
// Returns the route state and the interface index of the detected uplink.
// The index is stored in Manager.uplinkIfIdx and used by ControlFunc to
// bind awl sockets to the uplink via IP_BOUND_IF / IPV6_BOUND_IF.
func (m *Manager) setupClientRoutes(tunIfName string) (*darwinRouteState, int, error) {
	ifName, _, ifIdx, err := detectUplinkInterface()
	if err != nil {
		return nil, 0, fmt.Errorf("detect uplink interface: %w", err)
	}

	state := &darwinRouteState{
		tunIfName: tunIfName,
		uplink:    ifName,
	}

	// ── IPv4 covering routes ──────────────────────────────────────────────
	// Use two /1 routes instead of modifying 0.0.0.0/0 directly.  This keeps
	// the original default route intact (needed for uplink detection on
	// teardown and by any tool that inspects the routing table).
	for _, cidr := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
		if out, err := exec.Command(
			"route", "-q", "-n", "add", "-inet", cidr, "-iface", tunIfName,
		).CombinedOutput(); err != nil {
			_ = m.teardownClientRoutes(state)
			return nil, 0, fmt.Errorf("add IPv4 route %s via %s: %v: %s",
				cidr, tunIfName, err, strings.TrimSpace(string(out)))
		}
	}
	state.ipv4RoutesAdded = true

	// ── IPv6 covering routes ──────────────────────────────────────────────
	ipv6ok := true
	for _, cidr := range []string{"::/1", "8000::/1"} {
		if out, err := exec.Command(
			"route", "-q", "-n", "add", "-inet6", cidr, "-iface", tunIfName,
		).CombinedOutput(); err != nil {
			logger.Warnf("darwin: add IPv6 route %s via %s (IPv6 gateway may not work): %v: %s",
				cidr, tunIfName, err, strings.TrimSpace(string(out)))
			ipv6ok = false
			break
		}
	}
	if ipv6ok {
		state.ipv6RoutesAdded = true
	}

	// ── pf kill-switch (strict anti-loop) ────────────────────────────────
	// Ensure the pf main ruleset references our anchors.
	if err := m.ensurePFSetup(); err != nil {
		_ = m.teardownClientRoutes(state)
		return nil, 0, fmt.Errorf("pf setup for client kill-switch: %w", err)
	}

	uid := os.Getuid()
	filterRules := fmt.Sprintf(
		// Allow awl's own sockets (bound to uplink via IP_BOUND_IF) through.
		// pf user matching works for TCP/UDP; the IP_BOUND_IF binding in
		// ControlFunc ensures these sockets are on the uplink interface.
		"pass out quick on %s user %d\n"+
			// Drop everything else trying to leave via the uplink.  Other
			// applications' traffic goes via TUN (default route); this rule
			// is the hard fence that prevents leaks if TUN is briefly down.
			"block drop out quick on %s\n",
		ifName, uid, ifName,
	)
	if err := runPfctlWithStdin(filterRules, "-a", awlPFAnchor+"/filter", "-f", "-"); err != nil {
		m.releasePFSetup()
		_ = m.teardownClientRoutes(state)
		return nil, 0, fmt.Errorf("load pf client filter rules: %w", err)
	}
	state.pfFilterLoaded = true

	logger.Infof("darwin: gateway client routes installed via %s (uplink: %s, uid: %d)",
		tunIfName, ifName, uid)
	return state, ifIdx, nil
}

// teardownClientRoutes reverses setupClientRoutes. Idempotent and safe to
// call on partially-set-up state.
func (m *Manager) teardownClientRoutes(state *darwinRouteState) error {
	if state == nil {
		return nil
	}
	var errs []error

	// Flush the kill-switch anchor first so traffic can flow normally while
	// we remove the covering routes.
	if state.pfFilterLoaded {
		if err := runPfctlCmd("-a", awlPFAnchor+"/filter", "-F", "all"); err != nil {
			logger.Warnf("darwin: flush pf filter anchor: %v", err)
		}
		m.releasePFSetup()
		state.pfFilterLoaded = false
	}

	// Remove IPv4 covering routes.
	if state.ipv4RoutesAdded {
		for _, cidr := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
			if out, err := exec.Command(
				"route", "-q", "-n", "delete", "-inet", cidr,
			).CombinedOutput(); err != nil {
				errs = append(errs, fmt.Errorf("delete IPv4 route %s: %v: %s",
					cidr, err, strings.TrimSpace(string(out))))
			}
		}
		state.ipv4RoutesAdded = false
	}

	// Remove IPv6 covering routes.
	if state.ipv6RoutesAdded {
		for _, cidr := range []string{"::/1", "8000::/1"} {
			if out, err := exec.Command(
				"route", "-q", "-n", "delete", "-inet6", cidr,
			).CombinedOutput(); err != nil {
				errs = append(errs, fmt.Errorf("delete IPv6 route %s: %v: %s",
					cidr, err, strings.TrimSpace(string(out))))
			}
		}
		state.ipv6RoutesAdded = false
	}

	return errors.Join(errs...)
}
