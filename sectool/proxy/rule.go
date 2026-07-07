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
	// Adapter column only shows when a sidecar has scoped a rule; absent for plain proxy use
	hasAdapters := slices.ContainsFunc(rules, func(r protocol.RuleEntry) bool {
		return r.Adapter != ""
	})

	t := cliutil.NewTable(os.Stdout)
	tr := util.TruncateString

	header := table.Row{"Rule ID"}
	if hasLabels {
		header = append(header, "Label")
	}
	header = append(header, "Type", "Regex", "Find", "Replace")
	if hasAdapters {
		header = append(header, "Adapter")
	}
	t.AppendHeader(header)

	for _, r := range rules {
		regex := ""
		if r.IsRegex {
			regex = "yes"
		}
		row := table.Row{r.RuleID}
		if hasLabels {
			row = append(row, r.Label)
		}
		row = append(row, r.Type, regex, tr(r.Find, 30), tr(r.Replace, 30))
		if hasAdapters {
			row = append(row, r.Adapter)
		}
		t.AppendRow(row)
	}
	t.Render()
	cliutil.Summary(os.Stdout, len(rules), "rule", "rules")
}

func ruleAdd(mcpURL string, ruleType, find, replace, label string, isRegex bool) error {
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
		Find:    find,
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
	if resp.Adapter != "" {
		fmt.Printf("Adapter: %s\n", resp.Adapter)
	}
	if resp.IsRegex {
		fmt.Println("Mode: regex")
	}
	if resp.Find != "" {
		fmt.Printf("Find: `%s`\n", resp.Find)
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
