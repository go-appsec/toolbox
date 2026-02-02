package proxy

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/go-appsec/llm-security-toolbox/sectool/cliutil"
	"github.com/go-appsec/llm-security-toolbox/sectool/mcpclient"
	"github.com/go-appsec/llm-security-toolbox/sectool/protocol"
)

func ruleList(mcpURL string, timeout time.Duration, websocket bool, limit int) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	client, err := mcpclient.Connect(ctx, mcpURL)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	typeFilter := "http"
	if websocket {
		typeFilter = "websocket"
	}

	resp, err := client.ProxyRuleList(ctx, typeFilter, limit)
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

func printRuleTable(rules []protocol.RuleEntry) {
	hasLabels := slices.ContainsFunc(rules, func(r protocol.RuleEntry) bool {
		return r.Label != ""
	})

	if hasLabels {
		fmt.Println("| rule_id | label | type | regex | match | replace |")
		fmt.Println("|---------|-------|------|-------|-------|---------|")
		for _, r := range rules {
			regex := ""
			if r.IsRegex {
				regex = "yes"
			}
			fmt.Printf("| %s | %s | %s | %s | %s | %s |\n",
				r.RuleID, cliutil.EscapeMarkdown(r.Label), r.Type, regex,
				cliutil.EscapeMarkdown(truncate(r.Match, 30)),
				cliutil.EscapeMarkdown(truncate(r.Replace, 30)))
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
				r.RuleID, r.Type, regex,
				cliutil.EscapeMarkdown(truncate(r.Match, 30)),
				cliutil.EscapeMarkdown(truncate(r.Replace, 30)))
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

func ruleAdd(mcpURL string, timeout time.Duration, ruleType, match, replace, label string, isRegex bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	client, err := mcpclient.Connect(ctx, mcpURL)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	resp, err := client.ProxyRuleAdd(ctx, mcpclient.RuleAddOpts{
		Label:   label,
		Type:    ruleType,
		IsRegex: isRegex,
		Match:   match,
		Replace: replace,
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

func ruleUpdate(mcpURL string, timeout time.Duration, ruleID, ruleType, match, replace, label string, isRegex *bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	client, err := mcpclient.Connect(ctx, mcpURL)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	resp, err := client.ProxyRuleUpdate(ctx, ruleID, mcpclient.RuleUpdateOpts{
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

func ruleDelete(mcpURL string, timeout time.Duration, ruleID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	client, err := mcpclient.Connect(ctx, mcpURL)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	if err := client.ProxyRuleDelete(ctx, ruleID); err != nil {
		return fmt.Errorf("rule delete failed: %w", err)
	}

	fmt.Printf("Deleted rule `%s`\n", ruleID)
	return nil
}
