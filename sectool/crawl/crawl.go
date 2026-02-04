package crawl

import (
	"context"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jedib0t/go-pretty/v6/table"

	"github.com/go-appsec/llm-security-toolbox/sectool/bundle"
	"github.com/go-appsec/llm-security-toolbox/sectool/cliutil"
	"github.com/go-appsec/llm-security-toolbox/sectool/mcpclient"
	"github.com/go-appsec/llm-security-toolbox/sectool/protocol"
)

func create(mcpURL string, timeout time.Duration, urls, flows, domains []string, label string, maxDepth, maxRequests int, delay time.Duration, parallelism int, includeSubdomains, submitForms, ignoreRobots bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	client, err := mcpclient.Connect(ctx, mcpURL)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	var includeSubdomainsPtr *bool
	if !includeSubdomains {
		includeSubdomainsPtr = &includeSubdomains
	}

	var delayStr string
	if delay > 0 {
		delayStr = delay.String()
	}

	resp, err := client.CrawlCreate(ctx, mcpclient.CrawlCreateOpts{
		Label:             label,
		SeedURLs:          strings.Join(urls, ","),
		SeedFlows:         strings.Join(flows, ","),
		Domains:           strings.Join(domains, ","),
		MaxDepth:          maxDepth,
		MaxRequests:       maxRequests,
		Delay:             delayStr,
		Parallelism:       parallelism,
		IncludeSubdomains: includeSubdomainsPtr,
		SubmitForms:       submitForms,
		IgnoreRobots:      ignoreRobots,
	})
	if err != nil {
		return fmt.Errorf("crawl create failed: %w", err)
	}

	fmt.Println(cliutil.Bold("Crawl Session Created"))
	fmt.Println()
	fmt.Printf("Session ID: %s\n", cliutil.ID(resp.SessionID))
	if resp.Label != "" {
		fmt.Printf("Label: %s\n", cliutil.ID(resp.Label))
	}
	fmt.Printf("State: %s\n", resp.State)
	fmt.Printf("Created: %s\n", resp.CreatedAt)
	fmt.Println()

	// Prefer label for status command hint if available
	statusRef := resp.SessionID
	if resp.Label != "" {
		statusRef = resp.Label
	}
	cliutil.HintCommand(os.Stdout, "To check status", "sectool crawl status "+statusRef)
	cliutil.HintCommand(os.Stdout, "To view results", "sectool crawl list "+statusRef)
	cliutil.HintCommand(os.Stdout, "To stop", "sectool crawl stop "+statusRef)

	return nil
}

func seed(mcpURL string, timeout time.Duration, sessionID string, urls, flows []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	client, err := mcpclient.Connect(ctx, mcpURL)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	resp, err := client.CrawlSeed(ctx, sessionID, strings.Join(urls, ","), strings.Join(flows, ","))
	if err != nil {
		return fmt.Errorf("crawl seed failed: %w", err)
	}

	fmt.Printf("Added %d seed(s) to session `%s`\n", resp.AddedCount, sessionID)

	return nil
}

func status(mcpURL string, timeout time.Duration, sessionID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	client, err := mcpclient.Connect(ctx, mcpURL)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	resp, err := client.CrawlStatus(ctx, sessionID)
	if err != nil {
		return fmt.Errorf("crawl status failed: %w", err)
	}

	fmt.Println(cliutil.Bold("Crawl Status"))
	fmt.Println()
	fmt.Printf("State: %s\n", cliutil.Bold(resp.State))
	fmt.Printf("URLs Queued: %d\n", resp.URLsQueued)
	fmt.Printf("URLs Visited: %d\n", resp.URLsVisited)
	fmt.Printf("URLs Errored: %d\n", resp.URLsErrored)
	fmt.Printf("Forms Discovered: %d\n", resp.FormsDiscovered)
	fmt.Printf("Duration: %s\n", resp.Duration)
	fmt.Printf("Last Activity: %s\n", resp.LastActivity)
	if resp.ErrorMessage != "" {
		fmt.Printf("Error: %s\n", cliutil.Error(resp.ErrorMessage))
	}

	return nil
}

func summary(mcpURL string, timeout time.Duration, sessionID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	client, err := mcpclient.Connect(ctx, mcpURL)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	resp, err := client.CrawlPoll(ctx, sessionID, mcpclient.CrawlPollOpts{
		OutputMode: "summary",
	})
	if err != nil {
		return fmt.Errorf("crawl summary failed: %w", err)
	}

	fmt.Println(cliutil.Bold("Crawl Summary"))
	fmt.Println()
	fmt.Printf("Session: %s | State: %s | Duration: %s\n", cliutil.ID(resp.SessionID), cliutil.Bold(resp.State), resp.Duration)
	fmt.Println()

	if len(resp.Aggregates) == 0 {
		cliutil.NoResults(os.Stdout, "No traffic captured.")
		return nil
	}

	t := cliutil.NewTable(os.Stdout)
	t.AppendHeader(table.Row{"Host", "Path", "Method", "Status", "Count"})
	t.SetRowPainter(cliutil.StatusRowPainter(3))

	for _, agg := range resp.Aggregates {
		t.AppendRow(table.Row{agg.Host, agg.Path, agg.Method, agg.Status, agg.Count})
	}
	t.Render()
	cliutil.Summary(os.Stdout, len(resp.Aggregates), "unique request pattern", "unique request patterns")

	return nil
}

func list(mcpURL string, timeout time.Duration, sessionID, listType, host, path, method, status, contains, containsBody, excludeHost, excludePath, since string, limit, offset int) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	client, err := mcpclient.Connect(ctx, mcpURL)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	// Map CLI listType to output_mode
	outputMode := "flows"
	switch listType {
	case "forms":
		outputMode = "forms"
	case "errors":
		outputMode = "errors"
	}

	resp, err := client.CrawlPoll(ctx, sessionID, mcpclient.CrawlPollOpts{
		OutputMode:   outputMode,
		Host:         host,
		Path:         path,
		Method:       method,
		Status:       status,
		Contains:     contains,
		ContainsBody: containsBody,
		ExcludeHost:  excludeHost,
		ExcludePath:  excludePath,
		Since:        since,
		Limit:        limit,
		Offset:       offset,
	})
	if err != nil {
		return fmt.Errorf("crawl list failed: %w", err)
	}

	switch outputMode {
	case "forms":
		if len(resp.Forms) == 0 {
			cliutil.NoResults(os.Stdout, "No forms discovered.")
			return nil
		}
		for i, form := range resp.Forms {
			if i > 0 {
				fmt.Println()
			}
			fmt.Printf("%s on %s\n\n", cliutil.Bold("Form "+form.FormID), form.URL)
			fmt.Printf("Action: %s\n", form.Action)
			fmt.Printf("Method: %s\n", form.Method)
			if form.HasCSRF {
				fmt.Printf("CSRF Token: %s\n", cliutil.Success("detected"))
			}
			if len(form.Inputs) > 0 {
				fmt.Println()
				t := cliutil.NewTable(os.Stdout)
				t.AppendHeader(table.Row{"Name", "Type", "Value", "Required"})
				for _, input := range form.Inputs {
					required := ""
					if input.Required {
						required = "yes"
					}
					t.AppendRow(table.Row{input.Name, input.Type, input.Value, required})
				}
				t.Render()
			}
		}
		cliutil.Summary(os.Stdout, len(resp.Forms), "form", "forms")

	case "errors":
		if len(resp.Errors) == 0 {
			cliutil.NoResults(os.Stdout, "No errors encountered.")
			return nil
		}
		t := cliutil.NewTable(os.Stdout)
		t.AppendHeader(table.Row{"URL", "Status", "Error"})
		for _, e := range resp.Errors {
			statusStr := ""
			if e.Status > 0 {
				statusStr = strconv.Itoa(e.Status)
			}
			t.AppendRow(table.Row{e.URL, statusStr, e.Error})
		}
		t.Render()
		cliutil.Summary(os.Stdout, len(resp.Errors), "error", "errors")

	default: // flows
		if len(resp.Flows) == 0 {
			cliutil.NoResults(os.Stdout, "No flows found.")
			return nil
		}
		t := cliutil.NewTable(os.Stdout)
		t.AppendHeader(table.Row{"Flow ID", "Method", "Host", "Path", "Status", "Size"})
		t.SetRowPainter(cliutil.StatusRowPainter(4))
		for _, flow := range resp.Flows {
			t.AppendRow(table.Row{flow.FlowID, flow.Method, flow.Host, flow.Path, flow.Status, flow.ResponseLength})
		}
		t.Render()
		cliutil.Summary(os.Stdout, len(resp.Flows), "flow", "flows")
		if len(resp.Flows) == limit && limit > 0 {
			cliutil.Hint(os.Stdout, fmt.Sprintf("More results may be available. Use --offset %d to paginate.", offset+limit))
		}
		if len(resp.Flows) > 0 {
			lastFlow := resp.Flows[len(resp.Flows)-1]
			cliutil.HintCommand(os.Stdout, "To list flows after this", fmt.Sprintf("sectool crawl list %s --since %s", sessionID, lastFlow.FlowID))
		}
		cliutil.HintCommand(os.Stdout, "To export for editing/replay", "sectool crawl export <flow_id>")
	}

	return nil
}

func sessions(mcpURL string, timeout time.Duration, limit int) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	client, err := mcpclient.Connect(ctx, mcpURL)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	resp, err := client.CrawlSessions(ctx, limit)
	if err != nil {
		return fmt.Errorf("crawl sessions failed: %w", err)
	}

	if len(resp.Sessions) == 0 {
		cliutil.NoResults(os.Stdout, "No crawl sessions.")
		cliutil.HintCommand(os.Stdout, "To create one", "sectool crawl create --url <url>")
		return nil
	}

	// Check if any session has a label
	hasLabels := slices.ContainsFunc(resp.Sessions, func(s protocol.CrawlSession) bool {
		return s.Label != ""
	})

	t := cliutil.NewTable(os.Stdout)
	if hasLabels {
		t.AppendHeader(table.Row{"Session ID", "Label", "State", "Created At"})
		for _, sess := range resp.Sessions {
			t.AppendRow(table.Row{sess.SessionID, sess.Label, sess.State, sess.CreatedAt})
		}
	} else {
		t.AppendHeader(table.Row{"Session ID", "State", "Created At"})
		for _, sess := range resp.Sessions {
			t.AppendRow(table.Row{sess.SessionID, sess.State, sess.CreatedAt})
		}
	}
	t.Render()
	cliutil.Summary(os.Stdout, len(resp.Sessions), "session", "sessions")

	return nil
}

func stop(mcpURL string, timeout time.Duration, sessionID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	client, err := mcpclient.Connect(ctx, mcpURL)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	if err := client.CrawlStop(ctx, sessionID); err != nil {
		return fmt.Errorf("crawl stop failed: %w", err)
	}

	fmt.Printf("Crawl session `%s` stopped.\n", sessionID)

	return nil
}

func export(mcpURL string, timeout time.Duration, flowID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	client, err := mcpclient.Connect(ctx, mcpURL)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	resp, err := client.CrawlGet(ctx, flowID)
	if err != nil {
		return fmt.Errorf("get flow: %w", err)
	}

	reqBody, err := bundle.DecodeBase64Body(resp.ReqBody)
	if err != nil {
		return fmt.Errorf("decode request body: %w", err)
	}

	respBody, err := bundle.DecodeBase64Body(resp.RespBody)
	if err != nil {
		return fmt.Errorf("decode response body: %w", err)
	}

	bundleDir, err := bundle.Write(flowID,
		resp.URL, resp.Method, resp.ReqHeaders, reqBody,
		resp.RespHeaders, respBody)
	if err != nil {
		return fmt.Errorf("write bundle: %w", err)
	}

	fmt.Printf("Exported flow `%s` to `%s/`\n", flowID, bundleDir)
	fmt.Println()
	fmt.Println("Files:")
	fmt.Println("- request.http - HTTP request headers")
	fmt.Println("- body - request body (edit this)")
	fmt.Println("- request.meta.json - metadata")
	if resp.RespHeaders != "" {
		fmt.Println("- response.http - response headers")
		fmt.Println("- response.body - response body")
	}
	fmt.Println()
	fmt.Printf("To replay: `sectool replay send --bundle %s`\n", flowID)

	return nil
}
