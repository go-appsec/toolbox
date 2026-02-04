package cliutil

import (
	"fmt"
	"io"
	"os"
)

// Hint prints a muted hint message.
func Hint(w io.Writer, message string) {
	if w == nil {
		w = os.Stdout
	}
	_, _ = fmt.Fprintln(w, Muted(message))
}

// HintCommand prints a command suggestion with description.
func HintCommand(w io.Writer, desc, cmd string) {
	if w == nil {
		w = os.Stdout
	}
	_, _ = fmt.Fprintf(w, "%s: %s\n", Muted(desc), ID(cmd))
}

// Summary prints a count summary line.
func Summary(w io.Writer, count int, singular, plural string) {
	if w == nil {
		w = os.Stdout
	}
	noun := plural
	if count == 1 {
		noun = singular
	}
	_, _ = fmt.Fprintf(w, "\n%s\n", Muted(fmt.Sprintf("%d %s", count, noun)))
}

// NoResults prints a "no results" message.
func NoResults(w io.Writer, message string) {
	if w == nil {
		w = os.Stdout
	}
	_, _ = fmt.Fprintln(w, Muted(message))
}
