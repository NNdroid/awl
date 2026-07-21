//go:build darwin

package netstate

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"

	"golang.org/x/sys/unix"
)

// Manager owns the macOS OS network state behind AWL's VPN gateway feature.
//
// Socket anti-loop (equivalent of Linux SO_MARK + fwmark):
//
//	ControlFunc returns a function that binds each new libp2p / SOCKS5 socket
//	to the physical uplink interface via IP_BOUND_IF / IPV6_BOUND_IF.  This
//	guarantees that AWL's own p2p traffic is never routed into the TUN tunnel,
//	preventing the forwarding loop that would otherwise occur when the client
//	default route points at TUN.
//
// Server-side NAT:
//
//	EnableServerNAT sets IPv4/IPv6 ip_forward via sysctl and loads a pf
//	MASQUERADE (nat) rule for the awl subnet via the physical uplink.  IPv6
//	forwarding is delegated to the userspace nat66Engine (service layer) —
//	macOS pf has no stateful MASQUERADE for IPv6.
//
// Client-side routes:
//
//	EnableClientRoutes installs two /1 IPv4 and two /1 IPv6 covering routes
//	via TUN (overriding the default without deleting it) and loads a pf
//	kill-switch anchor that hard-blocks any non-AWL traffic leaking through
//	the physical uplink.
//
// pf lifecycle:
//
//	Both Enable* methods call ensurePFSetup which reference-counts pf usage:
//	the first caller saves the in-memory ruleset, enables pf if necessary, and
//	prepends the com.awl/* anchor references to the main ruleset.  The last
//	Disable* caller flushes the anchors and restores the original ruleset via
//	releasePFSetup.
type Manager struct {
	mu         sync.Mutex
	routeState *darwinRouteState
	natState   *darwinNATState

	// uplinkIfIdx is the net.Interface.Index of the physical uplink detected
	// when client routes are installed.  Zero means client mode is inactive.
	// Read by ControlFunc concurrently with Enable/DisableClientRoutes.
	uplinkIfIdx atomic.Int32

	// pf lifecycle fields — guarded by mu.
	pfRefCount   int    // number of features (client / server) using pf
	pfWasEnabled bool   // whether pf was already enabled before we touched it
	savedPFRules string // original in-memory ruleset, restored when refCount → 0
}

// NewManager returns the macOS Manager.
func NewManager() *Manager {
	return &Manager{}
}

// Start is a no-op on macOS: there is no long-running background goroutine
// needed (unlike Linux's netlink route-change monitor).
func (m *Manager) Start(_ context.Context) error { return nil }

// ControlFunc returns a per-socket control function that binds each new TCP/UDP
// socket to the physical uplink interface when client gateway mode is active.
//
// This is the macOS analogue of Linux's SO_MARK + ip-rule fwmark: instead of
// marking packets and routing them via a separate table, we bind the socket
// directly to the uplink NIC so the kernel bypasses the TUN default route for
// AWL's own connections.  IP_BOUND_IF (IPv4, value 25) and IPV6_BOUND_IF
// (IPv6, value 125) are the standard macOS socket options for interface binding.
//
// The pf kill-switch anchor in EnableClientRoutes adds a second layer: even if
// a socket somehow escapes the IP_BOUND_IF binding, pf blocks its traffic
// unless it comes from the AWL process UID.
func (m *Manager) ControlFunc() func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		idx := int(m.uplinkIfIdx.Load())
		if idx == 0 {
			// Client mode not active — no binding needed.
			return nil
		}

		// Determine IP family from network string (tcp4/tcp6/udp4/udp6/ip4/ip6).
		isIPv6 := strings.Contains(network, "6") ||
			(strings.HasSuffix(network, "6") || network == "ip6")

		var bindErr error
		err := c.Control(func(fd uintptr) {
			if isIPv6 {
				// IPV6_BOUND_IF = 125 on Darwin.
				bindErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF, idx)
			} else {
				// IP_BOUND_IF = 25 on Darwin.
				bindErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF, idx)
			}
		})
		if err != nil {
			return fmt.Errorf("ControlFunc: socket control: %w", err)
		}
		if bindErr != nil {
			return fmt.Errorf("ControlFunc: bind socket to uplink (idx %d): %w", idx, bindErr)
		}
		return nil
	}
}

// EnableClientRoutes installs the gateway client covering routes and the pf
// kill-switch. Idempotent: a second call while routes are installed is a no-op.
func (m *Manager) EnableClientRoutes(tunIfName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.routeState != nil {
		return nil
	}
	state, uplinkIdx, err := m.setupClientRoutes(tunIfName)
	if err != nil {
		return fmt.Errorf("setup gateway routes: %w", err)
	}
	m.routeState = state
	m.uplinkIfIdx.Store(int32(uplinkIdx))
	return nil
}

// DisableClientRoutes removes the gateway client covering routes and the pf
// kill-switch. Idempotent; a no-op when routes are not installed.
func (m *Manager) DisableClientRoutes() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.routeState == nil {
		return nil
	}
	state := m.routeState
	m.routeState = nil
	m.uplinkIfIdx.Store(0)
	return m.teardownClientRoutes(state)
}

// ClientRoutesActive reports whether client covering routes are currently installed.
func (m *Manager) ClientRoutesActive() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.routeState != nil
}

// EnableServerNAT configures the exit-node data path (ip_forward + pf
// MASQUERADE for IPv4; sysctl for IPv6 forwarding used by nat66Engine).
// Idempotent: a second call while NAT is configured is a no-op.
func (m *Manager) EnableServerNAT(awlSubnet, _ /* awlSubnet6 — handled by nat66Engine */, tunIfName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.natState != nil {
		return nil
	}
	state, err := m.setupDarwinNAT(awlSubnet, tunIfName)
	if err != nil {
		return fmt.Errorf("setup NAT: %w", err)
	}
	m.natState = state
	return nil
}

// DisableServerNAT reverses EnableServerNAT. Idempotent; a no-op when NAT is
// not configured.
func (m *Manager) DisableServerNAT() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.natState == nil {
		return nil
	}
	state := m.natState
	m.natState = nil
	return m.teardownDarwinNAT(state)
}

// ServerNATActive reports whether the exit-node NAT is currently configured.
func (m *Manager) ServerNATActive() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.natState != nil
}

// ── pf lifecycle helpers ──────────────────────────────────────────────────────

// ensurePFSetup increments the pf reference count. On the first call it:
//  1. Checks whether pf is already enabled.
//  2. Enables pf (pfctl -e) if it was not.
//  3. Saves the current in-memory ruleset for later restoration.
//  4. Reloads the main ruleset with com.awl/* anchor references prepended.
//
// Must be called with m.mu held.
func (m *Manager) ensurePFSetup() error {
	if m.pfRefCount > 0 {
		m.pfRefCount++
		return nil
	}

	m.pfWasEnabled = isPFEnabled()

	// Enable pf. pfctl -e returns exit 1 with "already enabled" when pf is
	// already running — that is not an error.
	if out, err := exec.Command("pfctl", "-e").CombinedOutput(); err != nil {
		if !strings.Contains(string(out), "already enabled") {
			// Best-effort log; we'll still try to load rules.
			logger.Warnf("darwin: pfctl -e: %v: %s", err, filterPFOutput(string(out)))
		}
	}

	// Save in-memory rules for restoration.
	saved, err := savePFRules()
	if err != nil {
		return fmt.Errorf("save pf rules: %w", err)
	}
	m.savedPFRules = saved

	// Reload the main ruleset with our com.awl/* anchor references at the top.
	if err := loadMainRulesWithAWLAnchors(saved); err != nil {
		return fmt.Errorf("inject AWL anchors into pf ruleset: %w", err)
	}

	m.pfRefCount++
	return nil
}

// releasePFSetup decrements the pf reference count. When it reaches zero it:
//  1. Flushes all rules in the com.awl anchor tree.
//  2. Restores the saved in-memory ruleset (or falls back to /etc/pf.conf).
//  3. Disables pf if we were the ones who enabled it.
//
// Must be called with m.mu held.
func (m *Manager) releasePFSetup() {
	if m.pfRefCount <= 0 {
		return
	}
	m.pfRefCount--
	if m.pfRefCount > 0 {
		return
	}

	// Flush our entire anchor tree.
	if err := runPfctlCmd("-a", awlPFAnchor, "-F", "all"); err != nil {
		logger.Warnf("darwin: flush com.awl anchor: %v", err)
	}

	// Restore the original ruleset.
	restorePFRules(m.savedPFRules)
	m.savedPFRules = ""

	// Disable pf only if we were the ones who enabled it.
	if !m.pfWasEnabled {
		if err := runPfctlCmd("-d"); err != nil {
			logger.Warnf("darwin: pfctl -d: %v", err)
		}
	}
}
