package cliutil

import (
	"io"
	"os"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
)

// NewTable creates a new styled table writer.
// If w is nil, uses os.Stdout.
func NewTable(w io.Writer) table.Writer {
	if w == nil {
		w = os.Stdout
	}

	t := table.NewWriter()
	t.SetOutputMirror(w)

	if Output.ColorsEnabled() {
		t.SetStyle(StyleLight())
	} else {
		t.SetStyle(StyleSimple())
	}

	return t
}

// StatusRowPainter returns a row painter function that colors rows based on HTTP status.
// statusColIdx is the 0-based index of the status column in the row.
func StatusRowPainter(statusColIdx int) func(row table.Row) text.Colors {
	return func(row table.Row) text.Colors {
		if !Output.ColorsEnabled() {
			return nil
		} else if statusColIdx >= len(row) {
			return nil
		}

		status, ok := row[statusColIdx].(int)
		if !ok {
			return nil
		}

		return text.Colors{StatusColor(status)}
	}
}
