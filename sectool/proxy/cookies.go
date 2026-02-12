package proxy

import (
	"context"
	"fmt"
	"os"

	"github.com/jedib0t/go-pretty/v6/table"

	"github.com/go-appsec/toolbox/sectool/cliutil"
	"github.com/go-appsec/toolbox/sectool/mcpclient"
	"github.com/go-appsec/toolbox/sectool/util"
)

func cookies(mcpURL, name, domain string) error {
	ctx := context.Background()

	client, err := mcpclient.Connect(ctx, mcpURL)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	resp, err := client.CookieJar(ctx, mcpclient.CookieJarOpts{
		Name:   name,
		Domain: domain,
	})
	if err != nil {
		return fmt.Errorf("cookie jar failed: %w", err)
	}

	if len(resp.Cookies) == 0 {
		cliutil.NoResults(os.Stdout, "No cookies found in proxy history.")
		return nil
	}

	t := cliutil.NewTable(os.Stdout)
	t.AppendHeader(table.Row{"Name", "Domain", "Path", "Secure", "HttpOnly", "SameSite", "Expires", "Value", "Flow ID"})

	for _, c := range resp.Cookies {
		val := util.TruncateString(c.Value, 40)
		t.AppendRow(table.Row{c.Name, c.Domain, c.Path, boolFlag(c.Secure), boolFlag(c.HttpOnly), c.SameSite, c.Expires, val, c.FlowID})
	}
	t.Render()
	cliutil.Summary(os.Stdout, len(resp.Cookies), "cookie", "cookies")

	return nil
}

func boolFlag(v bool) string {
	if v {
		return "yes"
	}
	return ""
}
