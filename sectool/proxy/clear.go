package proxy

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/go-appsec/toolbox/sectool/mcpclient"
)

// pageLimit is the proxy_poll batch size used during ranged clears.
const pageLimit = 500

type clearOpts struct {
	flow   string
	before string
	after  string
	from   string
	to     string
	all    bool
}

// modeCount returns the number of distinct modes selected. (--from / --to count as one mode together.)
func (o clearOpts) modeCount() int {
	var n int
	if o.flow != "" {
		n++
	}
	if o.before != "" {
		n++
	}
	if o.after != "" {
		n++
	}
	if o.from != "" || o.to != "" {
		n++
	}
	if o.all {
		n++
	}
	return n
}

func clear(mcpURL string, opts clearOpts) error {
	ctx := context.Background()
	client, err := mcpclient.Connect(ctx, mcpURL)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	// Single-flow mode short-circuits the paging loop
	if opts.flow != "" {
		dp, dr, skipped, err := client.ClearHistory(ctx, []string{opts.flow})
		if err != nil {
			return fmt.Errorf("clear history: %w", err)
		}
		// A noted flow shows up in `skipped`; that's a deliberate retain, not a typo
		if dp+dr == 0 && !slices.Contains(skipped, opts.flow) {
			return fmt.Errorf("flow_id not found: %s", opts.flow)
		}
		printClearResult(dp, dr, skipped)
		return nil
	}

	dp, dr, skipped, err := clearByPaging(ctx, client, opts)
	if err != nil {
		return err
	}
	if dp+dr+len(skipped) == 0 {
		fmt.Println("No matching flows to delete.")
		return nil
	}
	printClearResult(dp, dr, skipped)
	return nil
}

// clearByPaging walks proxy_poll one page at a time and deletes
// the in-scope flow_ids from each page before fetching the next.
func clearByPaging(ctx context.Context, client *mcpclient.Client, opts clearOpts) (deletedProxy, deletedReplay int, skippedNoted []string, err error) {
	if err := validateAnchors(ctx, client, opts); err != nil {
		return 0, 0, nil, err
	}

	deleteBatch := func(ids []string) error {
		if len(ids) == 0 {
			return nil
		}
		dp, dr, skipped, derr := client.ClearHistory(ctx, ids)
		if derr != nil {
			return fmt.Errorf("clear history: %w", derr)
		}
		deletedProxy += dp
		deletedReplay += dr
		skippedNoted = append(skippedNoted, skipped...)
		return nil
	}

	cls := newClassifier(opts)
	var cursor, deferred string

	for {
		page, perr := client.ProxyPoll(ctx, mcpclient.ProxyPollOpts{
			OutputMode: "flows",
			Since:      cursor,
			Limit:      pageLimit,
			Wait:       "0s", // paging loop terminates on the first empty page
		})
		if perr != nil {
			return deletedProxy, deletedReplay, skippedNoted, fmt.Errorf("fetch flows: %w", perr)
		}
		if len(page.Flows) == 0 {
			break
		}

		var (
			toDelete []string
			stop     bool
		)
		for _, f := range page.Flows {
			switch cls.classify(f.FlowID) {
			case decisionInclude:
				toDelete = append(toDelete, f.FlowID)
			case decisionStop:
				stop = true
			}
			if stop {
				break
			}
		}

		// Reverse-range is detectable only once --to is seen before --from
		if rerr := cls.reverseRangeError(); rerr != nil {
			return deletedProxy, deletedReplay, skippedNoted, rerr
		}

		// Previously-deferred cursor anchor: we've advanced past it, safe to delete now
		if deferred != "" {
			toDelete = append([]string{deferred}, toDelete...)
			deferred = ""
		}

		if stop {
			if err := deleteBatch(toDelete); err != nil {
				return deletedProxy, deletedReplay, skippedNoted, err
			}
			break
		}

		// Reserve the page's last flow_id from this round's deletion so the cursor always points at a live entry
		last := page.Flows[len(page.Flows)-1].FlowID
		if idx := slices.Index(toDelete, last); idx >= 0 {
			toDelete = slices.Delete(toDelete, idx, idx+1)
			deferred = last
		}
		if err := deleteBatch(toDelete); err != nil {
			return deletedProxy, deletedReplay, skippedNoted, err
		}
		cursor = last
	}

	if deferred != "" {
		if err := deleteBatch([]string{deferred}); err != nil {
			return deletedProxy, deletedReplay, skippedNoted, err
		}
	}
	return deletedProxy, deletedReplay, skippedNoted, nil
}

// validateAnchors checks each anchor flow_id resolves to a proxy or replay flow before any destructive call.
// Crawl flows are out of scope for clear because proxy_poll never surfaces them, so a
// crawl anchor would silently run the loop to completion against the wrong stream.
func validateAnchors(ctx context.Context, client *mcpclient.Client, opts clearOpts) error {
	anchors := []struct{ flag, id string }{
		{"--before", opts.before},
		{"--after", opts.after},
		{"--from", opts.from},
		{"--to", opts.to},
	}
	for _, a := range anchors {
		if a.id == "" {
			continue
		}
		resp, err := client.FlowGet(ctx, a.id, mcpclient.FlowGetOpts{Scope: "request_headers"})
		if err != nil {
			return fmt.Errorf("flow_id not found: %s", a.id)
		}
		if resp.Source != "proxy" && resp.Source != "replay" {
			return fmt.Errorf("%s flow_id %s is a %s flow; proxy clear only operates on proxy and replay history",
				a.flag, a.id, resp.Source)
		}
	}
	return nil
}

// classifier decides per-flow inclusion based on the active clear mode. State machine for
// --after / --from / --to: skipping -> including -> stopped. Anchor existence is checked up front
// by validateAnchors; this type only tracks the in-stream toggle plus the reverse-range diagnostic.
type classifier struct {
	mode             clearMode
	anchor           string // --before / --after pivot
	from, to         string // --from / --to range bounds
	including        bool   // for --after / --from / --to: have we crossed the lower bound yet?
	upperBeforeLower bool   // observed --to before --from (range is reversed)
	stopAfter        bool   // emit one more Include, then Stop (inclusive --to upper bound)
}

type clearMode int

const (
	modeAll clearMode = iota
	modeBefore
	modeAfter
	modeRange
)

type decision int

const (
	decisionSkip decision = iota
	decisionInclude
	decisionStop
)

func newClassifier(opts clearOpts) *classifier {
	switch {
	case opts.all:
		return &classifier{mode: modeAll, including: true}
	case opts.before != "":
		return &classifier{mode: modeBefore, anchor: opts.before, including: true}
	case opts.after != "":
		return &classifier{mode: modeAfter, anchor: opts.after}
	default:
		c := &classifier{mode: modeRange, from: opts.from, to: opts.to}
		if opts.from == "" {
			c.including = true
		}
		return c
	}
}

func (c *classifier) classify(flowID string) decision {
	if c.stopAfter {
		return decisionStop
	}
	switch c.mode {
	case modeAll:
		return decisionInclude
	case modeBefore:
		if flowID == c.anchor {
			return decisionStop
		}
		return decisionInclude
	case modeAfter:
		if c.including {
			return decisionInclude
		}
		if flowID == c.anchor {
			c.including = true
		}
		return decisionSkip
	case modeRange:
		// Resolve --from match first so a single id covering both bounds
		// (--from X --to X) doesn't trip the wrong-order check.
		if !c.including && c.from != "" && flowID == c.from {
			c.including = true
		}
		// Track --to even when not yet including so out-of-order ranges
		// surface via reverseRangeError before any deletion runs.
		if c.to != "" && flowID == c.to && !c.including {
			c.upperBeforeLower = true
		}
		if !c.including {
			return decisionSkip
		}
		if c.to != "" && flowID == c.to {
			// --to is inclusive: include this id, then stop on the next call
			c.stopAfter = true
		}
		return decisionInclude
	}
	return decisionSkip
}

// reverseRangeError reports a wrong-order range once --to has been observed before --from.
// Anchor existence is validated up front; the classifier no longer surfaces missing-anchor errors.
func (c *classifier) reverseRangeError() error {
	if c.upperBeforeLower {
		return errors.New("--from must come before --to chronologically")
	}
	return nil
}

func printClearResult(deletedProxy, deletedReplay int, skippedNoted []string) {
	total := deletedProxy + deletedReplay
	fmt.Printf("Deleted %d flow(s) (proxy=%d, replay=%d)\n", total, deletedProxy, deletedReplay)
	if len(skippedNoted) > 0 {
		fmt.Printf("Retained %d flow(s) referenced by saved notes: %s\n",
			len(skippedNoted), strings.Join(skippedNoted, ", "))
	}
}
