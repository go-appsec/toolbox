package cliutil

import (
	"bytes"
	"testing"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/stretchr/testify/assert"
)

func TestNewTable(t *testing.T) {
	// With colors disabled
	Output = &OutputConfig{
		Writer:    &bytes.Buffer{},
		ColorMode: ColorNever,
	}

	buf := &bytes.Buffer{}
	tw := NewTable(buf)
	assert.NotNil(t, tw)

	tw.AppendHeader(table.Row{"ID", "Name"})
	tw.AppendRow(table.Row{"1", "test"})
	tw.Render()

	output := buf.String()
	assert.Contains(t, output, "ID")
	assert.Contains(t, output, "NAME") // headers are uppercased
	assert.Contains(t, output, "test")
	assert.Contains(t, output, "+") // ASCII style
}

func TestNewTable_WithColors(t *testing.T) {
	Output = &OutputConfig{
		Writer:    &bytes.Buffer{},
		ColorMode: ColorAlways,
	}

	buf := &bytes.Buffer{}
	tw := NewTable(buf)
	assert.NotNil(t, tw)

	tw.AppendHeader(table.Row{"ID", "Name"})
	tw.AppendRow(table.Row{"1", "test"})
	tw.Render()

	output := buf.String()
	assert.Contains(t, output, "ID")
	assert.Contains(t, output, "test")
	assert.Contains(t, output, "┌") // Unicode style
}

func TestStatusRowPainter(t *testing.T) {
	Output = &OutputConfig{
		Writer:    &bytes.Buffer{},
		ColorMode: ColorAlways,
	}

	painter := StatusRowPainter(2)

	// Test with valid status
	row := table.Row{"abc", "GET", 200, "/api"}
	colors := painter(row)
	assert.NotNil(t, colors)

	// Test with index out of bounds
	shortRow := table.Row{"abc", "GET"}
	colors = painter(shortRow)
	assert.Nil(t, colors)

	// Test with non-int status
	badRow := table.Row{"abc", "GET", "200", "/api"}
	colors = painter(badRow)
	assert.Nil(t, colors)
}

func TestStatusRowPainter_ColorsDisabled(t *testing.T) {
	Output = &OutputConfig{
		Writer:    &bytes.Buffer{},
		ColorMode: ColorNever,
	}

	painter := StatusRowPainter(2)
	row := table.Row{"abc", "GET", 200, "/api"}
	colors := painter(row)
	assert.Nil(t, colors)
}
