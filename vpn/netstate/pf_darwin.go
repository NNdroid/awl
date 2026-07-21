//go:build darwin

package netstate

import (
	"fmt"
	"os/exec"
	"strings"
)

// awlPFAnchor is the pf anchor name used by awl. Sub-anchors are named
// awlPFAnchor/nat (server NAT rules) and awlPFAnchor/filter (client
// kill-switch rules). The main ruleset references com.awl/* so that both
// sub-anchors are evaluated automatically.
const awlPFAnchor = "com.awl"

// runPfctlCmd runs pfctl with the given args and returns a combined-output
// error on failure. Informational ALTQ noise is filtered from the message.
func runPfctlCmd(args ...string) error {
	out, err := exec.Command("pfctl", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("pfctl %s: %v: %s",
			strings.Join(args, " "), err, strings.TrimSpace(filterPFOutput(string(out))))
	}
	return nil
}

// runPfctlOutput runs pfctl and returns filtered stdout+stderr output.
func runPfctlOutput(args ...string) (string, error) {
	out, err := exec.Command("pfctl", args...).CombinedOutput()
	filtered := filterPFOutput(string(out))
	if err != nil {
		return filtered, fmt.Errorf("pfctl %s: %v", strings.Join(args, " "), err)
	}
	return filtered, nil
}

// runPfctlWithStdin runs pfctl with the provided stdin and returns an error
// on failure.
func runPfctlWithStdin(input string, args ...string) error {
	cmd := exec.Command("pfctl", args...)
	cmd.Stdin = strings.NewReader(input)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("pfctl %s: %v: %s",
			strings.Join(args, " "), err, strings.TrimSpace(filterPFOutput(string(out))))
	}
	return nil
}

// savePFRules captures the current in-memory pf NAT and filter rules as a
// string suitable for passing back to pfctl -f for restoration.
func savePFRules() (string, error) {
	nat, _ := runPfctlOutput("-s", "nat")
	rules, _ := runPfctlOutput("-s", "rules")
	combined := strings.TrimSpace(nat) + "\n" + strings.TrimSpace(rules)
	return strings.TrimSpace(combined), nil
}

// loadMainRulesWithAWLAnchors prepends nat-anchor and anchor references for
// com.awl/* to the supplied existing rules and reloads the main pf ruleset.
// If the existing rules already contain the awl anchor reference this is a
// no-op to avoid duplicating entries.
func loadMainRulesWithAWLAnchors(existingRules string) error {
	if strings.Contains(existingRules, awlPFAnchor) {
		// Already present — reload as-is to make sure pf is synced.
		return runPfctlWithStdin(existingRules, "-f", "-")
	}
	newRuleset := fmt.Sprintf(
		"nat-anchor \"%s/*\"\nanchor \"%s/*\"\n%s\n",
		awlPFAnchor, awlPFAnchor, existingRules,
	)
	return runPfctlWithStdin(newRuleset, "-f", "-")
}

// restorePFRules reloads a previously saved ruleset. If that fails it falls
// back to reloading /etc/pf.conf.
func restorePFRules(saved string) {
	if saved != "" {
		if err := runPfctlWithStdin(saved, "-f", "-"); err != nil {
			logger.Warnf("darwin: restore pf rules from memory: %v — falling back to /etc/pf.conf", err)
			_ = runPfctlCmd("-f", "/etc/pf.conf")
		}
		return
	}
	_ = runPfctlCmd("-f", "/etc/pf.conf")
}

// isPFEnabled reports whether pf is currently running.
func isPFEnabled() bool {
	out, _ := exec.Command("pfctl", "-s", "info").Output()
	return strings.Contains(string(out), "Status: Enabled")
}

// filterPFOutput strips ALTQ noise and blank lines from pfctl output so
// error messages stay readable.
func filterPFOutput(s string) string {
	var lines []string
	for _, line := range strings.Split(s, "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.Contains(t, "ALTQ") {
			continue
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

// sysctlGet reads a sysctl value by name and returns it as a trimmed string.
func sysctlGet(name string) (string, error) {
	out, err := exec.Command("sysctl", "-n", name).Output()
	if err != nil {
		return "", fmt.Errorf("sysctl -n %s: %w", name, err)
	}
	return strings.TrimSpace(string(out)), nil
}

// sysctlSet writes a sysctl value by name.
func sysctlSet(name, value string) error {
	out, err := exec.Command("sysctl", "-w", fmt.Sprintf("%s=%s", name, value)).CombinedOutput()
	if err != nil {
		return fmt.Errorf("sysctl -w %s=%s: %v: %s", name, value, err, strings.TrimSpace(string(out)))
	}
	return nil
}
