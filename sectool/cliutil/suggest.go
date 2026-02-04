package cliutil

import (
	"fmt"

	"github.com/agnivade/levenshtein"
)

// maxSuggestionDistance is the max edit distance for "did you mean" suggestions
const maxSuggestionDistance = 3

// UnknownSubcommandError returns an error for an unknown subcommand with a
// "did you mean" suggestion if a close match is found.
func UnknownSubcommandError(prefix, unknown string, validCommands []string) error {
	if best := findClosest(unknown, validCommands); best != "" {
		return fmt.Errorf("unknown %s subcommand: %s (did you mean %q?)", prefix, unknown, best)
	}
	return fmt.Errorf("unknown %s subcommand: %s", prefix, unknown)
}

// UnknownCommandError returns an error for an unknown command with a
// "did you mean" suggestion if a close match is found.
func UnknownCommandError(unknown string, validCommands []string) error {
	if best := findClosest(unknown, validCommands); best != "" {
		return fmt.Errorf("unknown command: %s (did you mean %q?)", unknown, best)
	}
	return fmt.Errorf("unknown command: %s", unknown)
}

// findClosest returns the closest match from candidates, or empty if none are close enough.
func findClosest(input string, candidates []string) string {
	var best string
	bestDist := maxSuggestionDistance + 1

	for _, c := range candidates {
		dist := levenshtein.ComputeDistance(input, c)
		if dist < bestDist {
			bestDist = dist
			best = c
		}
	}

	if bestDist <= maxSuggestionDistance {
		return best
	}
	return ""
}
