package proxy

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/jentfoo/llm-security-toolbox/sectool/service"
)

func ruleList(timeout time.Duration, websocket bool, limit int) error {
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

	resp, err := client.RuleList(ctx, &service.RuleListRequest{
		WebSocket: websocket,
		Limit:     limit,
	})
	if err != nil {
		return fmt.Errorf("rule list failed: %w", err)
	}

	if len(resp.Rules) == 0 {
		ruleType := "HTTP"
		if websocket {
			ruleType = "WebSocket"
		}
		fmt.Printf("No %s rules configured.\n", ruleType)
		return nil
	}

	printRuleTable(resp.Rules)
	return nil
}

func printRuleTable(rules []service.RuleEntry) {
	// Check if any rules have labels
	hasLabels := false
	for _, r := range rules {
		if r.Label != "" {
			hasLabels = true
			break
		}
	}

	if hasLabels {
		fmt.Println("| rule_id | label | type | regex | match | replace |")
		fmt.Println("|---------|-------|------|-------|-------|---------|")
		for _, r := range rules {
			regex := ""
			if r.IsRegex {
				regex = "yes"
			}
			fmt.Printf("| %s | %s | %s | %s | %s | %s |\n",
				r.RuleID,
				escapeMarkdown(r.Label),
				r.Type,
				regex,
				escapeMarkdown(truncate(r.Match, 30)),
				escapeMarkdown(truncate(r.Replace, 30)),
			)
		}
	} else {
		fmt.Println("| rule_id | type | regex | match | replace |")
		fmt.Println("|---------|------|-------|-------|---------|")
		for _, r := range rules {
			regex := ""
			if r.IsRegex {
				regex = "yes"
			}
			fmt.Printf("| %s | %s | %s | %s | %s |\n",
				r.RuleID,
				r.Type,
				regex,
				escapeMarkdown(truncate(r.Match, 30)),
				escapeMarkdown(truncate(r.Replace, 30)),
			)
		}
	}
	fmt.Printf("\n*%d rules*\n", len(rules))
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-2] + ".."
}

func ruleAdd(timeout time.Duration, websocket bool, ruleType, match, replace, label string, isRegex bool) error {
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

	resp, err := client.RuleAdd(ctx, &service.RuleAddRequest{
		WebSocket: websocket,
		Label:     label,
		Type:      ruleType,
		IsRegex:   isRegex,
		Match:     match,
		Replace:   replace,
	})
	if err != nil {
		return fmt.Errorf("rule add failed: %w", err)
	}

	fmt.Printf("Created rule `%s`\n", resp.RuleID)
	if resp.Label != "" {
		fmt.Printf("Label: %s\n", resp.Label)
	}
	fmt.Printf("Type: %s\n", resp.Type)
	if resp.IsRegex {
		fmt.Println("Mode: regex")
	}
	if resp.Match != "" {
		fmt.Printf("Match: `%s`\n", resp.Match)
	}
	if resp.Replace != "" {
		fmt.Printf("Replace: `%s`\n", resp.Replace)
	}
	return nil
}

func ruleUpdate(timeout time.Duration, ruleID, ruleType, match, replace, label string, isRegex bool) error {
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

	resp, err := client.RuleUpdate(ctx, &service.RuleUpdateRequest{
		RuleID:  ruleID,
		Label:   label,
		Type:    ruleType,
		IsRegex: isRegex,
		Match:   match,
		Replace: replace,
	})
	if err != nil {
		return fmt.Errorf("rule update failed: %w", err)
	}

	fmt.Printf("Updated rule `%s`\n", resp.RuleID)
	if resp.Label != "" {
		fmt.Printf("Label: %s\n", resp.Label)
	}
	fmt.Printf("Type: %s\n", resp.Type)
	if resp.IsRegex {
		fmt.Println("Mode: regex")
	}
	if resp.Match != "" {
		fmt.Printf("Match: `%s`\n", resp.Match)
	}
	if resp.Replace != "" {
		fmt.Printf("Replace: `%s`\n", resp.Replace)
	}
	return nil
}

func ruleDelete(timeout time.Duration, ruleID string) error {
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

	if _, err := client.RuleDelete(ctx, &service.RuleDeleteRequest{
		RuleID: ruleID,
	}); err != nil {
		return fmt.Errorf("rule delete failed: %w", err)
	}

	fmt.Printf("Deleted rule `%s`\n", ruleID)
	return nil
}
