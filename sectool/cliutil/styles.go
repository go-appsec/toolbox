package cliutil

import (
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
)

// StyleLight returns the primary table style with Unicode box-drawing characters.
func StyleLight() table.Style {
	return table.Style{
		Name: "Light",
		Box: table.BoxStyle{
			BottomLeft:       "└",
			BottomRight:      "┘",
			BottomSeparator:  "┴",
			EmptySeparator:   text.RepeatAndTrim(" ", text.StringWidthWithoutEscSequences("┼")),
			Left:             "│",
			LeftSeparator:    "├",
			MiddleHorizontal: "─",
			MiddleSeparator:  "┼",
			MiddleVertical:   "│",
			PaddingLeft:      " ",
			PaddingRight:     " ",
			PageSeparator:    "\n",
			Right:            "│",
			RightSeparator:   "┤",
			TopLeft:          "┌",
			TopRight:         "┐",
			TopSeparator:     "┬",
			UnfinishedRow:    " …",
		},
		Color: table.ColorOptions{
			Header: text.Colors{text.Bold},
		},
		Format: table.FormatOptions{
			Header: text.FormatUpper,
		},
		Options: table.Options{
			DrawBorder:      true,
			SeparateColumns: true,
			SeparateHeader:  true,
			SeparateRows:    false,
		},
	}
}

// StyleSimple returns a plain ASCII style for non-TTY output.
func StyleSimple() table.Style {
	return table.Style{
		Name: "Simple",
		Box: table.BoxStyle{
			BottomLeft:       "+",
			BottomRight:      "+",
			BottomSeparator:  "+",
			EmptySeparator:   " ",
			Left:             "|",
			LeftSeparator:    "+",
			MiddleHorizontal: "-",
			MiddleSeparator:  "+",
			MiddleVertical:   "|",
			PaddingLeft:      " ",
			PaddingRight:     " ",
			PageSeparator:    "\n",
			Right:            "|",
			RightSeparator:   "+",
			TopLeft:          "+",
			TopRight:         "+",
			TopSeparator:     "+",
			UnfinishedRow:    " ...",
		},
		Format: table.FormatOptions{
			Header: text.FormatUpper,
		},
		Options: table.Options{
			DrawBorder:      true,
			SeparateColumns: true,
			SeparateHeader:  true,
			SeparateRows:    false,
		},
	}
}
