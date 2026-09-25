//go:build windows

package netstate

import (
	"fmt"
	"net/netip"

	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// Uplink detection picks the host's physical uplink interface from the
// routing table: the interface carrying the best default route, excluding our
// own TUN. Used by the socket marker (binding libp2p sockets to the physical
// NIC via IP_UNICAST_IF) and by the exit-node NAT setup (enabling
// per-interface forwarding). The selection itself (bestUplink) is a pure
// function over a snapshot so it can be unit-tested without touching the live
// routing table; bestUplinkDefault builds the snapshot from the real table.
//
// The algorithm mirrors WireGuard for Windows (findDefaultLUID in
// tunnel/mtumonitor.go): among default routes (PrefixLength == 0) on
// operationally-up interfaces, excluding our own adapter, pick the lowest
// (route metric + interface metric).

// uplinkRoute is a snapshot of one default-route candidate.
type uplinkRoute struct {
	// IfLUID identifies the interface (winipcfg.LUID). Opaque in the
	// selection; only used for the exclusion match and for returning the
	// winner.
	IfLUID uint64
	// IfIndex is the interface index used for IP_UNICAST_IF / IPV6_UNICAST_IF.
	IfIndex uint32
	// NextHop is copied from the winning default route. It is used when
	// installing explicit gateway-client bypass routes on the physical uplink.
	NextHop netip.Addr
	// Metric is the effective priority: route metric + interface metric.
	Metric uint32
	// Up reports whether the interface is operationally up.
	Up bool
}

// bestUplink returns the candidate with the lowest Metric among routes that
// are Up and whose IfLUID differs from excludeLUID. Returns ok=false when no
// candidate qualifies (offline host, or the only default route is our own
// TUN). Ties are broken by first occurrence, matching table order.
func bestUplink(routes []uplinkRoute, excludeLUID uint64) (uplinkRoute, bool) {
	var best uplinkRoute
	found := false
	for _, r := range routes {
		if !r.Up || r.IfLUID == excludeLUID {
			continue
		}
		if !found || r.Metric < best.Metric {
			best = r
			found = true
		}
	}
	return best, found
}

// bestUplinkDefault scans the live routing table for the given address family
// and returns the uplink candidate per bestUplink. excludeLUID is the adapter
// to skip (our Wintun); pass 0 to exclude nothing. ok=false with err==nil
// means the scan worked but no uplink exists right now (offline host) —
// callers treat that as "index 0", not as a failure.
func bestUplinkDefault(family winipcfg.AddressFamily, excludeLUID winipcfg.LUID) (uplinkRoute, bool, error) {
	rows, err := winipcfg.GetIPForwardTable2(family)
	if err != nil {
		return uplinkRoute{}, false, fmt.Errorf("get IP forward table: %w", err)
	}

	candidates := make([]uplinkRoute, 0, 4)
	for i := range rows {
		r := &rows[i]
		if r.DestinationPrefix.PrefixLength != 0 {
			continue
		}
		// Interface rows can disappear between the table snapshot and these
		// lookups (adapter removal mid-scan) — skip candidates we cannot
		// fully qualify instead of failing the whole detection.
		ifRow, err := r.InterfaceLUID.Interface()
		if err != nil {
			continue
		}
		ipIface, err := r.InterfaceLUID.IPInterface(family)
		if err != nil {
			continue
		}
		candidates = append(candidates, uplinkRoute{
			IfLUID:  uint64(r.InterfaceLUID),
			IfIndex: r.InterfaceIndex,
			NextHop: r.NextHop.Addr(),
			Metric:  r.Metric + ipIface.Metric,
			Up:      ifRow.OperStatus == winipcfg.IfOperStatusUp,
		})
	}

	best, ok := bestUplink(candidates, uint64(excludeLUID))
	return best, ok, nil
}
