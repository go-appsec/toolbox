package oast

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/jentfoo/llm-security-toolbox/sectool/service"
)

func create(timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	workDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get working directory: %w", err)
	}

	client := service.NewClient(workDir, service.WithTimeout(timeout))
	if err := client.EnsureService(ctx); err != nil {
		return fmt.Errorf("failed to start service: %w (check %s)", err, client.LogPath())
	}

	resp, err := client.OastCreate(ctx)
	if err != nil {
		return fmt.Errorf("oast create failed: %w", err)
	}

	fmt.Println("## OAST Session Created")
	fmt.Println()
	fmt.Printf("ID: `%s`\n", resp.OastID)
	fmt.Printf("Domain: `%s`\n", resp.Domain)
	fmt.Println()
	fmt.Println("Use any subdomain for tagging (e.g., `sqli-test." + resp.Domain + "`)")
	fmt.Println()
	fmt.Printf("To poll for events: `sectool oast poll %s`\n", resp.OastID)

	return nil
}

func poll(timeout time.Duration, oastID, since string, wait time.Duration, limit int) error {
	// Extend timeout to include wait duration
	totalTimeout := timeout + wait
	ctx, cancel := context.WithTimeout(context.Background(), totalTimeout)
	defer cancel()

	workDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get working directory: %w", err)
	}

	client := service.NewClient(workDir, service.WithTimeout(totalTimeout))
	if err := client.EnsureService(ctx); err != nil {
		return fmt.Errorf("failed to start service: %w", err)
	}

	resp, err := client.OastPoll(ctx, &service.OastPollRequest{
		OastID: oastID,
		Since:  since,
		Wait:   wait.String(),
		Limit:  limit,
	})
	if err != nil {
		return fmt.Errorf("oast poll failed: %w", err)
	}

	// Format output as markdown table
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
			event.EventID,
			event.Time,
			strings.ToUpper(event.Type),
			event.SourceIP,
			escapeMarkdown(event.Subdomain),
		)
	}
	fmt.Printf("\n*%d event(s)*\n", len(resp.Events))

	if resp.DroppedCount > 0 {
		fmt.Printf("\n*Note: %d events were dropped due to buffer limit*\n", resp.DroppedCount)
	}

	// Show hints for next actions
	fmt.Printf("\nTo view event details: `sectool oast get %s <event_id>`\n", oastID)
	if len(resp.Events) > 0 {
		lastEvent := resp.Events[len(resp.Events)-1]
		fmt.Printf("To poll for new events: `sectool oast poll %s --since last`\n", oastID)
		fmt.Printf("Or after specific event: `sectool oast poll %s --since %s`\n", oastID, lastEvent.EventID)
	}

	return nil
}

func escapeMarkdown(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", "")
	return s
}

func get(timeout time.Duration, oastID, eventID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	workDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get working directory: %w", err)
	}

	client := service.NewClient(workDir, service.WithTimeout(timeout))
	if err := client.EnsureService(ctx); err != nil {
		return fmt.Errorf("failed to start service: %w (check %s)", err, client.LogPath())
	}

	resp, err := client.OastGet(ctx, &service.OastGetRequest{
		OastID:  oastID,
		EventID: eventID,
	})
	if err != nil {
		return fmt.Errorf("oast get failed: %w", err)
	}

	// Format output as markdown
	fmt.Printf("## OAST Event `%s`\n\n", resp.EventID)
	fmt.Printf("- Time: %s\n", resp.Time)
	fmt.Printf("- Type: %s\n", strings.ToUpper(resp.Type))
	fmt.Printf("- Source IP: %s\n", resp.SourceIP)
	fmt.Printf("- Subdomain: `%s`\n", resp.Subdomain)

	if len(resp.Details) > 0 {
		fmt.Println()
		for k, v := range resp.Details {
			if s, ok := v.(string); ok && len(s) > 0 {
				fmt.Printf("### %s\n\n", formatDetailKey(k))
				fmt.Println("```")
				fmt.Println(s)
				fmt.Println("```")
			} else {
				fmt.Printf("%s: %v\n", formatDetailKey(k), v)
			}
		}
	}

	return nil
}

func formatDetailKey(key string) string {
	// Convert snake_case to Title Case
	key = strings.ReplaceAll(key, "_", " ")
	words := strings.Fields(key)
	for i, word := range words {
		if len(word) > 0 {
			words[i] = strings.ToUpper(word[:1]) + word[1:]
		}
	}
	return strings.Join(words, " ")
}

func list(timeout time.Duration, limit int) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	workDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get working directory: %w", err)
	}

	client := service.NewClient(workDir, service.WithTimeout(timeout))
	if err := client.EnsureService(ctx); err != nil {
		return fmt.Errorf("failed to start service: %w (check %s)", err, client.LogPath())
	}

	resp, err := client.OastList(ctx, &service.OastListRequest{Limit: limit})
	if err != nil {
		return fmt.Errorf("oast list failed: %w", err)
	}

	if len(resp.Sessions) == 0 {
		fmt.Println("No active OAST sessions.")
		fmt.Println("\nTo create one: `sectool oast create`")
		return nil
	}

	// Format output as markdown table
	fmt.Println("| oast_id | domain | created_at |")
	fmt.Println("|---------|--------|------------|")
	for _, sess := range resp.Sessions {
		fmt.Printf("| %s | %s | %s |\n",
			sess.OastID,
			sess.Domain,
			sess.CreatedAt,
		)
	}
	fmt.Printf("\n*%d active session(s)*\n", len(resp.Sessions))

	return nil
}

func del(timeout time.Duration, oastID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	workDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get working directory: %w", err)
	}

	client := service.NewClient(workDir, service.WithTimeout(timeout))
	if err := client.EnsureService(ctx); err != nil {
		return fmt.Errorf("failed to start service: %w (check %s)", err, client.LogPath())
	}

	_, err = client.OastDelete(ctx, &service.OastDeleteRequest{
		OastID: oastID,
	})
	if err != nil {
		return fmt.Errorf("oast delete failed: %w", err)
	}

	fmt.Printf("OAST session `%s` deleted.\n", oastID)

	return nil
}
