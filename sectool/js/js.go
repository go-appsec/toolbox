package js

import (
	"context"
	"fmt"

	"github.com/jedib0t/go-pretty/v6/table"

	"github.com/go-appsec/toolbox/sectool/cliutil"
	"github.com/go-appsec/toolbox/sectool/mcpclient"
)

func run(mcpURL, flowID string) error {
	ctx := context.Background()

	client, err := mcpclient.Connect(ctx, mcpURL)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	resp, err := client.JSAnalyze(ctx, flowID)
	if err != nil {
		return fmt.Errorf("js_analyze failed: %w", err)
	}

	fmt.Printf("%s\n\n", cliutil.Bold("JS Analyze"))
	fmt.Printf("Flow %s, source=%s\n", cliutil.ID(flowID), resp.Source)
	fmt.Printf("Bytes=%d, script_blocks=%d, parse_errors=%d\n\n",
		resp.Stats.InputBytes, resp.Stats.ScriptBlocks, resp.Stats.ParseErrors)

	for _, w := range resp.Warnings {
		fmt.Printf("  %s %s\n", cliutil.Warning("!"), w)
	}
	if len(resp.Warnings) > 0 {
		fmt.Println()
	}

	if len(resp.Endpoints) > 0 {
		fmt.Printf("%s\n", cliutil.Bold("Endpoints"))
		t := cliutil.NewTable(nil)
		t.AppendHeader(table.Row{"Method", "URL", "Lib", "Last Flow"})
		for _, e := range resp.Endpoints {
			t.AppendRow(table.Row{e.Method, e.URL, e.Library, e.LastFlow})
		}
		t.Render()
		fmt.Println()
	}

	if len(resp.Routes) > 0 {
		fmt.Printf("%s\n", cliutil.Bold("Routes"))
		t := cliutil.NewTable(nil)
		t.AppendHeader(table.Row{"Path", "Framework"})
		for _, r := range resp.Routes {
			t.AppendRow(table.Row{r.Path, r.Framework})
		}
		t.Render()
		fmt.Println()
	}

	if len(resp.Secrets) > 0 {
		fmt.Printf("%s\n", cliutil.Bold("Secrets"))
		t := cliutil.NewTable(nil)
		t.AppendHeader(table.Row{"Kind", "Value"})
		for _, s := range resp.Secrets {
			t.AppendRow(table.Row{s.Kind, s.Value})
		}
		t.Render()
		fmt.Println()
	}

	if len(resp.ExternalScripts) > 0 {
		fmt.Printf("%s\n", cliutil.Bold("External Scripts"))
		for _, s := range resp.ExternalScripts {
			fmt.Printf("  %s\n", s)
		}
		fmt.Println()
	}

	if len(resp.SourceMaps) > 0 {
		fmt.Printf("%s\n", cliutil.Bold("Source Maps"))
		for _, s := range resp.SourceMaps {
			fmt.Printf("  %s\n", s)
		}
		fmt.Println()
	}

	if len(resp.Endpoints)+len(resp.Routes)+len(resp.Secrets)+len(resp.ExternalScripts) == 0 {
		fmt.Println("No API surface extracted.")
	}

	return nil
}
