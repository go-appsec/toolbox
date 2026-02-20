package proxy

import (
	"context"
	"fmt"
	"os"

	"github.com/jedib0t/go-pretty/v6/table"

	"github.com/go-appsec/toolbox/sectool/cliutil"
	"github.com/go-appsec/toolbox/sectool/mcpclient"
	"github.com/go-appsec/toolbox/sectool/protocol"
)

func summary(mcpURL string, source, host, path, method, status, searchHeader, searchBody, excludeHost, excludePath string) error {
	ctx := context.Background()

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
		SearchHeader: searchHeader,
		SearchBody:   searchBody,
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

	if resp.Note != "" {
		fmt.Println()
		fmt.Println(cliutil.Muted("Note: " + resp.Note))
	}

	return nil
}

func list(mcpURL string, source, host, path, method, status, searchHeader, searchBody, since, excludeHost, excludePath string, limit, offset int) error {
	ctx := context.Background()

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
		SearchHeader: searchHeader,
		SearchBody:   searchBody,
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

	if resp.Note != "" {
		fmt.Println()
		fmt.Println(cliutil.Muted("Note: " + resp.Note))
	}

	return nil
}

func get(mcpURL string, flowID, scope, pattern string) error {
	ctx := context.Background()

	client, err := mcpclient.Connect(ctx, mcpURL)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	resp, err := client.FlowGet(ctx, flowID, mcpclient.FlowGetOpts{
		Scope:   scope,
		Pattern: pattern,
	})
	if err != nil {
		return fmt.Errorf("proxy get failed: %w", err)
	}

	fmt.Printf("%s\n\n", cliutil.Bold("Flow Details"))
	fmt.Printf("Flow: %s\n", cliutil.ID(resp.FlowID))
	fmt.Printf("Method: %s\n", resp.Method)
	fmt.Printf("URL: %s\n", resp.URL)
	fmt.Printf("Status: %s %s\n", cliutil.FormatStatus(resp.Status), resp.StatusLine)
	fmt.Printf("Request Size: %d bytes\n", resp.ReqSize)
	fmt.Printf("Response Size: %d bytes\n", resp.RespSize)

	if resp.ReqHeaders != "" {
		fmt.Println()
		fmt.Println(cliutil.Bold("Request Headers"))
		fmt.Println(resp.ReqHeaders)
	}
	if resp.ReqBody != "" {
		fmt.Println(cliutil.Bold("Request Body"))
		fmt.Println(resp.ReqBody)
	}
	if resp.RespHeaders != "" {
		fmt.Println()
		fmt.Println(cliutil.Bold("Response Headers"))
		fmt.Println(resp.RespHeaders)
	}
	if resp.RespBody != "" {
		fmt.Println(cliutil.Bold("Response Body"))
		fmt.Println(resp.RespBody)
	}
	if resp.Note != "" {
		fmt.Println()
		fmt.Println(cliutil.Muted("Note: " + resp.Note))
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
