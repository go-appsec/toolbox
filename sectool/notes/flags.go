package notes

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/pflag"

	"github.com/go-appsec/toolbox/sectool/cliutil"
)

// helpSubcommand is the help subcommand name shared by dispatch and usage listing.
const helpSubcommand = "help"

// Notes subcommand names used in dispatch and usage listing.
const (
	notesSubcmdList   = "list"
	notesSubcmdGet    = "get"
	notesSubcmdDelete = "delete"
)

var notesSubcommands = []string{notesSubcmdList, notesSubcmdGet, notesSubcmdDelete, helpSubcommand}

func Parse(args []string, mcpURL string) error {
	if len(args) < 1 {
		printUsage()
		return errors.New("subcommand required")
	}

	switch args[0] {
	case notesSubcmdList:
		return parseList(args[1:], mcpURL)
	case notesSubcmdGet:
		return parseGet(args[1:], mcpURL)
	case notesSubcmdDelete:
		return parseDelete(args[1:], mcpURL)
	case helpSubcommand, "--help", "-h":
		printUsage()
		return nil
	default:
		return cliutil.UnknownSubcommandError("notes", args[0], notesSubcommands)
	}
}

func printUsage() {
	_, _ = fmt.Fprint(os.Stderr, `Usage: sectool notes <command> [options]

List and manage saved notes/findings. Requires the MCP server started with --notes.

---

notes list [options]

  List saved notes with optional filters.

  Options:
    --type <type>        filter by note type
    --flow-id <list>     comma-separated flow_ids notes must reference
    --contains <text>    case-insensitive substring search on content
    --limit <n>          maximum number of notes to return

---

notes get <note_id>

  Full content for a single note.

---

notes delete <note_id>

  Delete a note by ID.
`)
}

func parseList(args []string, mcpURL string) error {
	fs := pflag.NewFlagSet("notes list", pflag.ContinueOnError)
	fs.SetInterspersed(true)
	var noteType, flowIDs, contains string
	var limit int

	fs.StringVar(&noteType, "type", "", "filter by note type")
	fs.StringVar(&flowIDs, "flow-id", "", "filter to notes referencing these flow_ids (comma-separated)")
	fs.StringVar(&contains, "contains", "", "case-insensitive substring search on content")
	fs.IntVar(&limit, "limit", 0, "maximum number of notes to return")

	fs.Usage = func() {
		_, _ = fmt.Fprint(os.Stderr, `Usage: sectool notes list [options]

List saved notes.

Options:
`)
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	return list(mcpURL, listFilters{
		noteType: noteType,
		flowIDs:  parseIDList(flowIDs),
		contains: contains,
		limit:    limit,
	})
}

func parseGet(args []string, mcpURL string) error {
	fs := pflag.NewFlagSet("notes get", pflag.ContinueOnError)
	fs.SetInterspersed(true)

	fs.Usage = func() {
		_, _ = fmt.Fprint(os.Stderr, `Usage: sectool notes get <note_id>

Show full content for a single note.

Options:
`)
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return err
	} else if len(fs.Args()) < 1 {
		fs.Usage()
		return errors.New("note_id required (get from 'sectool notes list')")
	}

	return get(mcpURL, fs.Args()[0])
}

func parseDelete(args []string, mcpURL string) error {
	fs := pflag.NewFlagSet("notes delete", pflag.ContinueOnError)
	fs.SetInterspersed(true)

	fs.Usage = func() {
		_, _ = fmt.Fprint(os.Stderr, `Usage: sectool notes delete <note_id>

Delete a note by ID.

Options:
`)
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return err
	} else if len(fs.Args()) < 1 {
		fs.Usage()
		return errors.New("note_id required (get from 'sectool notes list')")
	}

	return del(mcpURL, fs.Args()[0])
}

// parseIDList splits a comma-separated id list, dropping empty entries.
func parseIDList(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == ',' })
}
