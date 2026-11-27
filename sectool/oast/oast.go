package oast

import (
	"context"
	"fmt"
	"os"
	"slices"
	"sort"
	"strings"

	"github.com/jedib0t/go-pretty/v6/table"

	"github.com/go-appsec/toolbox/sectool/cliutil"
	"github.com/go-appsec/toolbox/sectool/mcpclient"
	"github.com/go-appsec/toolbox/sectool/protocol"
)

func create(mcpURL string, label, redirect string) error {
	ctx := context.Background()

	client, err := mcpclient.Connect(ctx, mcpURL)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	resp, err := client.OastCreate(ctx, label, redirect)
	if err != nil {
		return fmt.Errorf("oast create failed: %w", err)
	}

	fmt.Println(cliutil.Bold("OAST Session Created"))
	fmt.Println()
	fmt.Printf("ID: %s\n", cliutil.ID(resp.OastID))
	fmt.Printf("Domain: %s\n", cliutil.ID(resp.Domain))
	if resp.Label != "" {
		fmt.Printf("Label: %s\n", cliutil.ID(resp.Label))
	}
	if redirect != "" {
		fmt.Printf("Redirect: %s\n", cliutil.ID(redirect))
	}
	fmt.Println()
	if resp.Label == "" {
		cliutil.Hint(os.Stdout, "Use any subdomain for tagging (e.g., sqli-test."+resp.Domain+")")
		fmt.Println()
	}
	pollRef := resp.OastID
	if resp.Label != "" {
		pollRef = resp.Label
	}
	cliutil.HintCommand(os.Stdout, "To poll for events", "sectool oast poll "+pollRef)

	return nil
}

func summary(mcpURL string, oastID string, opts mcpclient.OastPollOpts) error {
	ctx := context.Background()

	client, err := mcpclient.Connect(ctx, mcpURL)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	opts.OutputMode = "summary"
	resp, err := client.OastPoll(ctx, oastID, opts)
	if err != nil {
		return fmt.Errorf("oast summary failed: %w", err)
	}

	if len(resp.Aggregates) == 0 {
		cliutil.NoResults(os.Stdout, "No events received.")
		if resp.DroppedCount > 0 {
			cliutil.Hint(os.Stdout, fmt.Sprintf("Note: %d events were dropped due to buffer limit", resp.DroppedCount))
		}
		return nil
	}

	t := cliutil.NewTable(os.Stdout)
	t.AppendHeader(table.Row{"Subdomain", "Source IP", "Type", "Count"})
	for _, agg := range resp.Aggregates {
		t.AppendRow(table.Row{agg.Subdomain, agg.SourceIP, strings.ToUpper(agg.Type), agg.Count})
	}
	t.Render()
	cliutil.Summary(os.Stdout, len(resp.Aggregates), "unique interaction pattern", "unique interaction patterns")

	if resp.DroppedCount > 0 {
		cliutil.Hint(os.Stdout, fmt.Sprintf("Note: %d events were dropped due to buffer limit", resp.DroppedCount))
	}

	return nil
}

func poll(mcpURL string, oastID string, opts mcpclient.OastPollOpts) error {
	ctx := context.Background()

	client, err := mcpclient.Connect(ctx, mcpURL)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	opts.OutputMode = "events"
	resp, err := client.OastPoll(ctx, oastID, opts)
	if err != nil {
		return fmt.Errorf("oast poll failed: %w", err)
	}

	if len(resp.Events) == 0 {
		cliutil.NoResults(os.Stdout, "No events received.")
		if resp.DroppedCount > 0 {
			cliutil.Hint(os.Stdout, fmt.Sprintf("Note: %d events were dropped due to buffer limit", resp.DroppedCount))
		}
		return nil
	}

	t := cliutil.NewTable(os.Stdout)
	t.AppendHeader(table.Row{"Event ID", "Time", "Type", "Source IP", "Subdomain"})
	for _, event := range resp.Events {
		t.AppendRow(table.Row{event.EventID, event.Time, strings.ToUpper(event.Type), event.SourceIP, event.Subdomain})
	}
	t.Render()
	cliutil.Summary(os.Stdout, len(resp.Events), "event", "events")

	if resp.DroppedCount > 0 {
		cliutil.Hint(os.Stdout, fmt.Sprintf("Note: %d events were dropped due to buffer limit", resp.DroppedCount))
	}

	// Show hints for next actions
	cliutil.HintCommand(os.Stdout, "To view event details", "sectool oast get <event_id>")
	if len(resp.Events) > 0 {
		lastEvent := resp.Events[len(resp.Events)-1]
		cliutil.HintCommand(os.Stdout, "To poll for new events", fmt.Sprintf("sectool oast poll %s --since %s", oastID, lastEvent.EventID))
	}

	return nil
}

func get(mcpURL string, eventID string, fields string) error {
	ctx := context.Background()

	client, err := mcpclient.Connect(ctx, mcpURL)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	resp, err := client.OastGet(ctx, eventID, fields)
	if err != nil {
		return fmt.Errorf("oast get failed: %w", err)
	}

	fmt.Printf("%s\n\n", cliutil.Bold("OAST Event "+resp.EventID))
	fmt.Printf("Time: %s\n", resp.Time)
	fmt.Printf("Type: %s\n", strings.ToUpper(resp.Type))
	fmt.Printf("Source IP: %s\n", resp.SourceIP)
	fmt.Printf("Subdomain: %s\n", cliutil.ID(resp.Subdomain))

	if len(resp.Details) > 0 {
		// Display order: smtp envelope, target, headers, body, then remaining keys alphabetically
		orderedKeys := []string{"smtp_from", "smtp_to", "target", "headers", "body"}
		printed := make(map[string]bool, len(orderedKeys))
		for _, k := range orderedKeys {
			if v, ok := resp.Details[k]; ok {
				printed[k] = true
				printDetail(k, v)
			}
		}
		// Remaining keys (e.g. dns raw_request/raw_response) in sorted order
		var extra []string
		for k := range resp.Details {
			if !printed[k] {
				extra = append(extra, k)
			}
		}
		sort.Strings(extra)
		for _, k := range extra {
			printDetail(k, resp.Details[k])
		}
	}

	return nil
}

// printDetail renders a single detail key-value pair with title-cased key.
func printDetail(k string, v interface{}) {
	title := strings.ReplaceAll(k, "_", " ")
	words := strings.Fields(title)
	for i, word := range words {
		if len(word) > 0 {
			words[i] = strings.ToUpper(word[:1]) + word[1:]
		}
	}
	title = strings.Join(words, " ")

	if s, ok := v.(string); ok && len(s) > 0 {
		fmt.Println()
		fmt.Println(cliutil.Bold(title))
		fmt.Println(s)
	} else {
		fmt.Printf("%s: %v\n", title, v)
	}
}

func list(mcpURL string, limit int) error {
	ctx := context.Background()

	client, err := mcpclient.Connect(ctx, mcpURL)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	resp, err := client.OastList(ctx, limit)
	if err != nil {
		return fmt.Errorf("oast list failed: %w", err)
	}

	if len(resp.Sessions) == 0 {
		cliutil.NoResults(os.Stdout, "No active OAST sessions.")
		cliutil.HintCommand(os.Stdout, "To create one", "sectool oast create")
		return nil
	}

	hasLabels := slices.ContainsFunc(resp.Sessions, func(s protocol.OastSession) bool {
		return s.Label != ""
	})

	t := cliutil.NewTable(os.Stdout)
	if hasLabels {
		t.AppendHeader(table.Row{"OAST ID", "Label", "Domain", "Created At"})
		for _, sess := range resp.Sessions {
			t.AppendRow(table.Row{sess.OastID, sess.Label, sess.Domain, sess.CreatedAt})
		}
	} else {
		t.AppendHeader(table.Row{"OAST ID", "Domain", "Created At"})
		for _, sess := range resp.Sessions {
			t.AppendRow(table.Row{sess.OastID, sess.Domain, sess.CreatedAt})
		}
	}
	t.Render()
	cliutil.Summary(os.Stdout, len(resp.Sessions), "active session", "active sessions")

	return nil
}

func del(mcpURL string, oastID string) error {
	ctx := context.Background()

	client, err := mcpclient.Connect(ctx, mcpURL)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	if err := client.OastDelete(ctx, oastID); err != nil {
		return fmt.Errorf("oast delete failed: %w", err)
	}

	fmt.Printf("OAST session `%s` deleted.\n", oastID)

	return nil
}
