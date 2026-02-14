package proxy

import (
	"context"
	"fmt"
	"os"
	"slices"

	"github.com/jedib0t/go-pretty/v6/table"

	"github.com/go-appsec/toolbox/sectool/cliutil"
	"github.com/go-appsec/toolbox/sectool/mcpclient"
	"github.com/go-appsec/toolbox/sectool/protocol"
	"github.com/go-appsec/toolbox/sectool/util"
)

func ruleList(mcpURL string, websocket bool, limit int) error {
	ctx := context.Background()

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

	t := cliutil.NewTable(os.Stdout)
	tr := util.TruncateString

	if hasLabels {
		t.AppendHeader(table.Row{"Rule ID", "Label", "Type", "Regex", "Match", "Replace"})
		for _, r := range rules {
			regex := ""
			if r.IsRegex {
				regex = "yes"
			}
			t.AppendRow(table.Row{r.RuleID, r.Label, r.Type, regex, tr(r.Match, 30), tr(r.Replace, 30)})
		}
	} else {
		t.AppendHeader(table.Row{"Rule ID", "Type", "Regex", "Match", "Replace"})
		for _, r := range rules {
			regex := ""
			if r.IsRegex {
				regex = "yes"
			}
			t.AppendRow(table.Row{r.RuleID, r.Type, regex, tr(r.Match, 30), tr(r.Replace, 30)})
		}
	}
	t.Render()
	cliutil.Summary(os.Stdout, len(rules), "rule", "rules")
}

func ruleAdd(mcpURL string, ruleType, match, replace, label string, isRegex bool) error {
	ctx := context.Background()

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

func ruleDelete(mcpURL string, ruleID string) error {
	ctx := context.Background()

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
