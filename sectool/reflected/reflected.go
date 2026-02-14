package reflected

import (
	"context"
	"fmt"
	"strings"

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

	resp, err := client.FindReflected(ctx, flowID)
	if err != nil {
		return fmt.Errorf("find_reflected failed: %w", err)
	}

	if len(resp.Reflections) == 0 {
		fmt.Println("No reflections detected.")
		return nil
	}

	fmt.Printf("%s\n\n", cliutil.Bold("Reflected Parameters"))
	fmt.Printf("Flow %s — %d reflection(s) found\n\n", cliutil.ID(flowID), len(resp.Reflections))

	for _, r := range resp.Reflections {
		fmt.Printf("  %s %s (%s)\n", cliutil.Warning("→"), cliutil.Bold(r.Name), r.Source)
		fmt.Printf("    Value: %s\n", r.Value)
		fmt.Printf("    Found in: %s\n", strings.Join(r.Locations, ", "))
		for _, c := range r.Contexts {
			fmt.Printf("    Context: %s (encoding: %s)\n", c.Context, c.Encoding)
		}
		fmt.Println()
	}

	return nil
}
