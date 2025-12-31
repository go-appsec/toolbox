package proxy

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/jentfoo/llm-security-toolbox/sectool/service"
)

func list(timeout time.Duration, host, path, method, status, contains, containsBody, since, excludeHost, excludePath string, limit int) error {
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

	resp, err := client.ProxyList(ctx, &service.ProxyListRequest{
		Host:         host,
		Path:         path,
		Method:       method,
		Status:       status,
		Contains:     contains,
		ContainsBody: containsBody,
		Since:        since,
		ExcludeHost:  excludeHost,
		ExcludePath:  excludePath,
		Limit:        limit,
	})
	if err != nil {
		return fmt.Errorf("proxy list failed: %w", err)
	}

	// Format output as markdown
	if len(resp.Aggregates) > 0 {
		printAggregateTable(resp.Aggregates)
	} else if len(resp.Flows) > 0 {
		printFlowTable(resp.Flows)
	} else {
		fmt.Println("No matching entries found.")
	}

	return nil
}

func printAggregateTable(agg []service.AggregateEntry) {
	// Print markdown table
	fmt.Println("| host | path | method | status | count |")
	fmt.Println("|------|------|--------|--------|-------|")
	for _, e := range agg {
		fmt.Printf("| %s | %s | %s | %d | %d |\n",
			escapeMarkdown(e.Host),
			escapeMarkdown(e.Path),
			e.Method,
			e.Status,
			e.Count,
		)
	}
	fmt.Printf("\n*%d unique request patterns*\n", len(agg))
}

func printFlowTable(flows []service.FlowSummary) {
	// Print markdown table
	fmt.Println("| flow_id | method | host | path | status | size |")
	fmt.Println("|---------|--------|------|------|--------|------|")
	for _, f := range flows {
		fmt.Printf("| %s | %s | %s | %s | %d | %d |\n",
			f.FlowID,
			f.Method,
			escapeMarkdown(f.Host),
			escapeMarkdown(f.Path),
			f.Status,
			f.ResponseLength,
		)
	}
	fmt.Printf("\n*%d flows*\n", len(flows))

	// Show hint for --since last
	if len(flows) > 0 {
		lastFlow := flows[len(flows)-1]
		fmt.Printf("\nTo list new flows: `sectool proxy list --since last`\n")
		fmt.Printf("Or after specific flow: `sectool proxy list --since %s`\n", lastFlow.FlowID)
	}
}
