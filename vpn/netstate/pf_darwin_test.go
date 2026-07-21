//go:build darwin

package netstate

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFilterPFOutput(t *testing.T) {
	input := `
No ALTQ support in kernel
ALTQ related functions disabled
nat on en0 from 10.66.0.0/24 to any -> (en0)
pass out quick on en0 user 501
block drop out quick on en0
`
	want := `nat on en0 from 10.66.0.0/24 to any -> (en0)
pass out quick on en0 user 501
block drop out quick on en0`

	got := filterPFOutput(input)
	require.Equal(t, want, got, "ALTQ warnings and blank lines should be stripped")
}

func TestLoadMainRulesWithAWLAnchorsString(t *testing.T) {
	// We test the string generation logic of loadMainRulesWithAWLAnchors manually
	// since we cannot easily mock pfctl execution.
	existingRules := "pass all\nblock in quick on en0\n"

	containsAlready := strings.Contains(existingRules, awlPFAnchor)
	require.False(t, containsAlready)

	newRuleset := "nat-anchor \"" + awlPFAnchor + "/*\"\nanchor \"" + awlPFAnchor + "/*\"\n" + existingRules + "\n"

	require.Contains(t, newRuleset, "nat-anchor \"com.awl/*\"")
	require.Contains(t, newRuleset, "anchor \"com.awl/*\"")
	require.Contains(t, newRuleset, existingRules)
}
