package oast

import (
	"context"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/jedib0t/go-pretty/v6/table"

	"github.com/go-appsec/llm-security-toolbox/sectool/cliutil"
	"github.com/go-appsec/llm-security-toolbox/sectool/mcpclient"
	"github.com/go-appsec/llm-security-toolbox/sectool/protocol"
)

func create(mcpURL string, timeout time.Duration, label string) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	client, err := mcpclient.Connect(ctx, mcpURL)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	resp, err := client.OastCreate(ctx, label)
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
	fmt.Println()
	cliutil.Hint(os.Stdout, "Use any subdomain for tagging (e.g., sqli-test."+resp.Domain+")")
	fmt.Println()
	pollRef := resp.OastID
	if resp.Label != "" {
		pollRef = resp.Label
	}
	cliutil.HintCommand(os.Stdout, "To poll for events", "sectool oast poll "+pollRef)

	return nil
}

func summary(mcpURL string, timeout time.Duration, oastID, since, eventType string, wait time.Duration, limit int) error {
	totalTimeout := timeout + wait
	ctx, cancel := context.WithTimeout(context.Background(), totalTimeout)
	defer cancel()

	client, err := mcpclient.Connect(ctx, mcpURL)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	resp, err := client.OastPoll(ctx, oastID, mcpclient.OastPollOpts{
		OutputMode: "summary",
		Since:      since,
		EventType:  eventType,
		Wait:       wait.String(),
		Limit:      limit,
	})
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

func poll(mcpURL string, timeout time.Duration, oastID, since, eventType string, wait time.Duration, limit int) error {
	totalTimeout := timeout + wait
	ctx, cancel := context.WithTimeout(context.Background(), totalTimeout)
	defer cancel()

	client, err := mcpclient.Connect(ctx, mcpURL)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	resp, err := client.OastPoll(ctx, oastID, mcpclient.OastPollOpts{
		OutputMode: "events",
		Since:      since,
		EventType:  eventType,
		Wait:       wait.String(),
		Limit:      limit,
	})
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
	cliutil.HintCommand(os.Stdout, "To view event details", fmt.Sprintf("sectool oast get %s <event_id>", oastID))
	if len(resp.Events) > 0 {
		lastEvent := resp.Events[len(resp.Events)-1]
		cliutil.HintCommand(os.Stdout, "To poll for new events", fmt.Sprintf("sectool oast poll %s --since %s", oastID, lastEvent.EventID))
	}

	return nil
}

func get(mcpURL string, timeout time.Duration, oastID, eventID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	client, err := mcpclient.Connect(ctx, mcpURL)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	resp, err := client.OastGet(ctx, oastID, eventID)
	if err != nil {
		return fmt.Errorf("oast get failed: %w", err)
	}

	fmt.Printf("%s\n\n", cliutil.Bold("OAST Event "+resp.EventID))
	fmt.Printf("Time: %s\n", resp.Time)
	fmt.Printf("Type: %s\n", strings.ToUpper(resp.Type))
	fmt.Printf("Source IP: %s\n", resp.SourceIP)
	fmt.Printf("Subdomain: %s\n", cliutil.ID(resp.Subdomain))

	if len(resp.Details) > 0 {
		fmt.Println()
		for k, v := range resp.Details {
			// Convert snake_case key to Title Case
			title := strings.ReplaceAll(k, "_", " ")
			words := strings.Fields(title)
			for i, word := range words {
				if len(word) > 0 {
					words[i] = strings.ToUpper(word[:1]) + word[1:]
				}
			}
			title = strings.Join(words, " ")

			if s, ok := v.(string); ok && len(s) > 0 {
				fmt.Printf("### %s\n\n", title)
				fmt.Println("```")
				fmt.Println(s)
				fmt.Println("```")
			} else {
				fmt.Printf("%s: %v\n", title, v)
			}
		}
	}

	return nil
}

func list(mcpURL string, timeout time.Duration, limit int) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

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

func del(mcpURL string, timeout time.Duration, oastID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

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
