package notes

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/go-appsec/toolbox/sectool/cliutil"
	"github.com/go-appsec/toolbox/sectool/mcpclient"
	"github.com/go-appsec/toolbox/sectool/protocol"
	"github.com/go-appsec/toolbox/sectool/util"
)

// contentCellMaxLen bounds note content shown in list blocks.
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

	for _, n := range resp.Notes {
		printNoteBrief(n)
		fmt.Println()
	}
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

	printNote(*note)

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

// printNoteHeader renders the id, type, and flows lines shared by note views.
func printNoteHeader(n protocol.NoteEntry) {
	fmt.Printf("%s %s\n", cliutil.Bold("Note id:"), cliutil.ID(n.NoteID))
	fmt.Printf("Type: %s\n", n.Type)
	if len(n.FlowIDs) > 0 {
		fmt.Printf("Flows: %s\n", strings.Join(n.FlowIDs, ", "))
	}
	fmt.Println("Description:")
}

// printNote renders one note as a stacked block with full content.
func printNote(n protocol.NoteEntry) {
	printNoteHeader(n)
	fmt.Println(strings.TrimRight(n.Content, "\n"))
}

// printNoteBrief renders a note with collapsed, truncated content for list view.
func printNoteBrief(n protocol.NoteEntry) {
	printNoteHeader(n)
	fmt.Println(contentCell(n.Content))
}

// contentCell collapses whitespace and truncates content for single-line display.
func contentCell(s string) string {
	return util.TruncateString(strings.Join(strings.Fields(s), " "), contentCellMaxLen)
}
