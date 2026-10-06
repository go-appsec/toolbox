package notes

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/jedib0t/go-pretty/v6/table"

	"github.com/go-appsec/toolbox/sectool/cliutil"
	"github.com/go-appsec/toolbox/sectool/mcpclient"
	"github.com/go-appsec/toolbox/sectool/util"
)

// contentCellMaxLen bounds note content shown in list rows.
const contentCellMaxLen = 60

// listFilters carries the notes list command's filter selections.
type listFilters struct {
	noteType string
	flowIDs  []string
	contains string
	limit    int
}

func list(mcpURL string, f listFilters) error {
	ctx := context.Background()

	client, err := mcpclient.Connect(ctx, mcpURL)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	resp, err := client.NotesList(ctx, mcpclient.NotesListOpts{
		Type:     f.noteType,
		FlowIDs:  f.flowIDs,
		Contains: f.contains,
		Limit:    f.limit,
	})
	if err != nil {
		return fmt.Errorf("notes list failed: %w", err)
	}

	if len(resp.Notes) == 0 {
		cliutil.NoResults(os.Stdout, "No notes found.")
		return nil
	}

	t := cliutil.NewTable(os.Stdout)
	t.AppendHeader(table.Row{"Note ID", "Type", "Flows", "Content"})
	for _, n := range resp.Notes {
		t.AppendRow(table.Row{n.NoteID, n.Type, strings.Join(n.FlowIDs, ","), contentCell(n.Content)})
	}
	t.Render()
	cliutil.Summary(os.Stdout, len(resp.Notes), "note", "notes")

	cliutil.HintCommand(os.Stdout, "To view note details", "sectool notes get <note_id>")

	return nil
}

func get(mcpURL, noteID string) error {
	ctx := context.Background()

	client, err := mcpclient.Connect(ctx, mcpURL)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	note, err := client.NotesGet(ctx, noteID)
	if err != nil {
		return fmt.Errorf("notes get failed: %w", err)
	}

	fmt.Printf("%s\n", cliutil.Bold("Note "+note.NoteID))
	fmt.Printf("Type: %s\n", note.Type)
	if len(note.FlowIDs) > 0 {
		fmt.Printf("Flows: %s\n", strings.Join(note.FlowIDs, ", "))
	}
	fmt.Println()
	fmt.Println(note.Content)

	return nil
}

func del(mcpURL, noteID string) error {
	ctx := context.Background()

	client, err := mcpclient.Connect(ctx, mcpURL)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	if err := client.NotesDelete(ctx, noteID); err != nil {
		return fmt.Errorf("notes delete failed: %w", err)
	}

	fmt.Printf("Note `%s` deleted.\n", noteID)

	return nil
}

// contentCell collapses whitespace and truncates content for single-row display.
func contentCell(s string) string {
	return util.TruncateString(strings.Join(strings.Fields(s), " "), contentCellMaxLen)
}
