package proxy

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/jedib0t/go-pretty/v6/table"

	"github.com/go-appsec/llm-security-toolbox/sectool/cliutil"
	"github.com/go-appsec/llm-security-toolbox/sectool/mcpclient"
	"github.com/go-appsec/llm-security-toolbox/sectool/protocol"
)

func summary(mcpURL string, timeout time.Duration, source, host, path, method, status, contains, containsBody, excludeHost, excludePath string) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	client, err := mcpclient.Connect(ctx, mcpURL)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	resp, err := client.ProxyPoll(ctx, mcpclient.ProxyPollOpts{
		OutputMode:   "summary",
		Source:       source,
		Host:         host,
		Path:         path,
		Method:       method,
		Status:       status,
		Contains:     contains,
		ContainsBody: containsBody,
		ExcludeHost:  excludeHost,
		ExcludePath:  excludePath,
	})
	if err != nil {
		return fmt.Errorf("proxy summary failed: %w", err)
	}

	if len(resp.Aggregates) > 0 {
		printAggregateTable(resp.Aggregates)
	} else {
		cliutil.NoResults(os.Stdout, "No matching entries found.")
	}

	return nil
}

func list(mcpURL string, timeout time.Duration, source, host, path, method, status, contains, containsBody, since, excludeHost, excludePath string, limit, offset int) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	client, err := mcpclient.Connect(ctx, mcpURL)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	resp, err := client.ProxyPoll(ctx, mcpclient.ProxyPollOpts{
		OutputMode:   "flows",
		Source:       source,
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
		Offset:       offset,
	})
	if err != nil {
		return fmt.Errorf("proxy list failed: %w", err)
	}

	if len(resp.Flows) > 0 {
		printFlowTable(resp.Flows)
	} else {
		cliutil.NoResults(os.Stdout, "No matching entries found.")
	}

	return nil
}

func printAggregateTable(agg []protocol.SummaryEntry) {
	t := cliutil.NewTable(os.Stdout)
	t.AppendHeader(table.Row{"Host", "Path", "Method", "Status", "Count"})
	t.SetRowPainter(cliutil.StatusRowPainter(3)) // status is column index 3

	for _, e := range agg {
		t.AppendRow(table.Row{e.Host, e.Path, e.Method, e.Status, e.Count})
	}
	t.Render()
	cliutil.Summary(os.Stdout, len(agg), "unique request pattern", "unique request patterns")
}

func printFlowTable(flows []protocol.FlowEntry) {
	t := cliutil.NewTable(os.Stdout)
	t.AppendHeader(table.Row{"Flow ID", "Method", "Host", "Path", "Status", "Size", "Source"})
	t.SetRowPainter(cliutil.StatusRowPainter(4)) // status is column index 4

	for _, f := range flows {
		t.AppendRow(table.Row{f.FlowID, f.Method, f.Host, f.Path, f.Status, f.ResponseLength, f.Source})
	}
	t.Render()
	cliutil.Summary(os.Stdout, len(flows), "flow", "flows")

	if len(flows) > 0 {
		lastFlow := flows[len(flows)-1]
		cliutil.HintCommand(os.Stdout, "To list flows after this", "sectool proxy list --since "+lastFlow.FlowID)
	}
}
