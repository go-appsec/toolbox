package oast

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

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

	fmt.Println("## OAST Session Created")
	fmt.Println()
	fmt.Printf("ID: `%s`\n", resp.OastID)
	fmt.Printf("Domain: `%s`\n", resp.Domain)
	if resp.Label != "" {
		fmt.Printf("Label: `%s`\n", resp.Label)
	}
	fmt.Println()
	fmt.Println("Use any subdomain for tagging (e.g., `sqli-test." + resp.Domain + "`)")
	fmt.Println()
	pollRef := resp.OastID
	if resp.Label != "" {
		pollRef = resp.Label
	}
	fmt.Printf("To poll for events: `sectool oast poll %s`\n", pollRef)

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
		fmt.Println("No events received.")
		if resp.DroppedCount > 0 {
			fmt.Printf("\n*Note: %d events were dropped due to buffer limit*\n", resp.DroppedCount)
		}
		return nil
	}

	fmt.Println("| subdomain | source_ip | type | count |")
	fmt.Println("|-----------|-----------|------|-------|")
	for _, agg := range resp.Aggregates {
		fmt.Printf("| %s | %s | %s | %d |\n",
			cliutil.EscapeMarkdown(agg.Subdomain), agg.SourceIP,
			strings.ToUpper(agg.Type), agg.Count)
	}
	fmt.Printf("\n*%d unique interaction patterns*\n", len(resp.Aggregates))

	if resp.DroppedCount > 0 {
		fmt.Printf("\n*Note: %d events were dropped due to buffer limit*\n", resp.DroppedCount)
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
		fmt.Println("No events received.")
		if resp.DroppedCount > 0 {
			fmt.Printf("\n*Note: %d events were dropped due to buffer limit*\n", resp.DroppedCount)
		}
		return nil
	}

	fmt.Println("| event_id | time | type | source_ip | subdomain |")
	fmt.Println("|----------|------|------|-----------|-----------|")
	for _, event := range resp.Events {
		fmt.Printf("| %s | %s | %s | %s | %s |\n",
			event.EventID, event.Time, strings.ToUpper(event.Type),
			event.SourceIP, cliutil.EscapeMarkdown(event.Subdomain))
	}
	fmt.Printf("\n*%d event(s)*\n", len(resp.Events))

	if resp.DroppedCount > 0 {
		fmt.Printf("\n*Note: %d events were dropped due to buffer limit*\n", resp.DroppedCount)
	}

	// Show hints for next actions
	fmt.Printf("\nTo view event details: `sectool oast get %s <event_id>`\n", oastID)
	if len(resp.Events) > 0 {
		lastEvent := resp.Events[len(resp.Events)-1]
		fmt.Printf("To poll for new events: `sectool oast poll %s --since %s`\n", oastID, lastEvent.EventID)
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

	fmt.Printf("## OAST Event `%s`\n\n", resp.EventID)
	fmt.Printf("- Time: %s\n", resp.Time)
	fmt.Printf("- Type: %s\n", strings.ToUpper(resp.Type))
	fmt.Printf("- Source IP: %s\n", resp.SourceIP)
	fmt.Printf("- Subdomain: `%s`\n", resp.Subdomain)

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
		fmt.Println("No active OAST sessions.")
		fmt.Println("\nTo create one: `sectool oast create`")
		return nil
	}

	hasLabels := slices.ContainsFunc(resp.Sessions, func(s protocol.OastSession) bool {
		return s.Label != ""
	})

	if hasLabels {
		fmt.Println("| oast_id | label | domain | created_at |")
		fmt.Println("|---------|-------|--------|------------|")
		for _, sess := range resp.Sessions {
			fmt.Printf("| %s | %s | %s | %s |\n",
				sess.OastID, sess.Label, sess.Domain, sess.CreatedAt)
		}
	} else {
		fmt.Println("| oast_id | domain | created_at |")
		fmt.Println("|---------|--------|------------|")
		for _, sess := range resp.Sessions {
			fmt.Printf("| %s | %s | %s |\n",
				sess.OastID, sess.Domain, sess.CreatedAt)
		}
	}
	fmt.Printf("\n*%d active session(s)*\n", len(resp.Sessions))

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
