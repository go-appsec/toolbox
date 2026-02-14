package mcpclient

import (
	"context"

	"github.com/go-appsec/toolbox/sectool/protocol"
)

// ProxyPoll calls proxy_poll and returns summary or list of flows.
func (c *Client) ProxyPoll(ctx context.Context, opts ProxyPollOpts) (*protocol.ProxyPollResponse, error) {
	args := make(map[string]interface{})
	if opts.OutputMode != "" {
		args["output_mode"] = opts.OutputMode
	}
	if opts.Source != "" {
		args["source"] = opts.Source
	}
	if opts.Host != "" {
		args["host"] = opts.Host
	}
	if opts.Path != "" {
		args["path"] = opts.Path
	}
	if opts.Method != "" {
		args["method"] = opts.Method
	}
	if opts.Status != "" {
		args["status"] = opts.Status
	}
	if opts.SearchHeader != "" {
		args["search_header"] = opts.SearchHeader
	}
	if opts.SearchBody != "" {
		args["search_body"] = opts.SearchBody
	}
	if opts.Since != "" {
		args["since"] = opts.Since
	}
	if opts.ExcludeHost != "" {
		args["exclude_host"] = opts.ExcludeHost
	}
	if opts.ExcludePath != "" {
		args["exclude_path"] = opts.ExcludePath
	}
	if opts.Limit > 0 {
		args["limit"] = opts.Limit
	}
	if opts.Offset > 0 {
		args["offset"] = opts.Offset
	}

	var resp protocol.ProxyPollResponse
	if err := c.CallToolJSON(ctx, "proxy_poll", args, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ProxyGet calls proxy_get and returns full request/response data.
func (c *Client) ProxyGet(ctx context.Context, flowID string, opts ProxyGetOpts) (*protocol.ProxyGetResponse, error) {
	args := map[string]interface{}{"flow_id": flowID}
	if opts.FullBody {
		args["full_body"] = true
	}
	if opts.Scope != "" {
		args["scope"] = opts.Scope
	}
	if opts.Pattern != "" {
		args["pattern"] = opts.Pattern
	}
	var resp protocol.ProxyGetResponse
	if err := c.CallToolJSON(ctx, "proxy_get", args, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ProxyRuleList calls proxy_rule_list and returns rules.
func (c *Client) ProxyRuleList(ctx context.Context, typeFilter string, limit int) (*protocol.RuleListResponse, error) {
	args := make(map[string]interface{})
	if typeFilter != "" {
		args["type_filter"] = typeFilter
	}
	if limit > 0 {
		args["limit"] = limit
	}

	var resp protocol.RuleListResponse
	if err := c.CallToolJSON(ctx, "proxy_rule_list", args, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ProxyRuleAdd calls proxy_rule_add and returns the created rule.
func (c *Client) ProxyRuleAdd(ctx context.Context, opts RuleAddOpts) (*protocol.RuleEntry, error) {
	args := map[string]interface{}{
		"type": opts.Type,
	}
	if opts.Match != "" {
		args["match"] = opts.Match
	}
	if opts.Replace != "" {
		args["replace"] = opts.Replace
	}
	if opts.Label != "" {
		args["label"] = opts.Label
	}
	if opts.IsRegex {
		args["is_regex"] = opts.IsRegex
	}

	var resp protocol.RuleEntry
	if err := c.CallToolJSON(ctx, "proxy_rule_add", args, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ProxyRuleDelete calls proxy_rule_delete.
func (c *Client) ProxyRuleDelete(ctx context.Context, ruleID string) error {
	_, err := c.CallTool(ctx, "proxy_rule_delete", map[string]interface{}{"rule_id": ruleID})
	return err
}

// CookieJar calls cookie_jar and returns extracted cookies.
func (c *Client) CookieJar(ctx context.Context, opts CookieJarOpts) (*protocol.CookieJarResponse, error) {
	args := make(map[string]interface{})
	if opts.Name != "" {
		args["name"] = opts.Name
	}
	if opts.Domain != "" {
		args["domain"] = opts.Domain
	}
	var resp protocol.CookieJarResponse
	if err := c.CallToolJSON(ctx, "cookie_jar", args, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ReplaySend calls replay_send and returns the result.
func (c *Client) ReplaySend(ctx context.Context, opts ReplaySendOpts) (*protocol.ReplaySendResponse, error) {
	args := map[string]interface{}{
		"flow_id": opts.FlowID,
	}
	if opts.Method != "" {
		args["method"] = opts.Method
	}
	if opts.Body != "" {
		args["body"] = opts.Body
	}
	if opts.Target != "" {
		args["target"] = opts.Target
	}
	if len(opts.AddHeaders) > 0 {
		args["add_headers"] = opts.AddHeaders
	}
	if len(opts.RemoveHeaders) > 0 {
		args["remove_headers"] = opts.RemoveHeaders
	}
	if opts.Path != "" {
		args["path"] = opts.Path
	}
	if opts.Query != "" {
		args["query"] = opts.Query
	}
	if len(opts.SetQuery) > 0 {
		args["set_query"] = opts.SetQuery
	}
	if len(opts.RemoveQuery) > 0 {
		args["remove_query"] = opts.RemoveQuery
	}
	if len(opts.SetJSON) > 0 {
		args["set_json"] = opts.SetJSON
	}
	if len(opts.RemoveJSON) > 0 {
		args["remove_json"] = opts.RemoveJSON
	}
	if opts.FollowRedirects {
		args["follow_redirects"] = opts.FollowRedirects
	}
	if opts.Force {
		args["force"] = opts.Force
	}

	var resp protocol.ReplaySendResponse
	if err := c.CallToolJSON(ctx, "replay_send", args, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ReplayGet calls replay_get and returns full response data.
func (c *Client) ReplayGet(ctx context.Context, replayID string) (*protocol.ReplayGetResponse, error) {
	args := map[string]interface{}{"replay_id": replayID, "full_body": true}
	var resp protocol.ReplayGetResponse
	if err := c.CallToolJSON(ctx, "replay_get", args, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// RequestSend calls request_send and returns the result.
func (c *Client) RequestSend(ctx context.Context, opts RequestSendOpts) (*protocol.ReplaySendResponse, error) {
	args := map[string]interface{}{
		"url": opts.URL,
	}
	if opts.Method != "" {
		args["method"] = opts.Method
	}
	if len(opts.Headers) > 0 {
		args["headers"] = opts.Headers
	}
	if opts.Body != "" {
		args["body"] = opts.Body
	}
	if opts.FollowRedirects {
		args["follow_redirects"] = opts.FollowRedirects
	}

	var resp protocol.ReplaySendResponse
	if err := c.CallToolJSON(ctx, "request_send", args, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// OastCreate calls oast_create and returns the session.
func (c *Client) OastCreate(ctx context.Context, label string) (*protocol.OastCreateResponse, error) {
	args := make(map[string]interface{})
	if label != "" {
		args["label"] = label
	}

	var resp protocol.OastCreateResponse
	if err := c.CallToolJSON(ctx, "oast_create", args, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// OastPoll calls oast_poll and returns summary or list of events.
func (c *Client) OastPoll(ctx context.Context, oastID string, opts OastPollOpts) (*protocol.OastPollResponse, error) {
	args := map[string]interface{}{
		"oast_id": oastID,
	}
	if opts.OutputMode != "" {
		args["output_mode"] = opts.OutputMode
	}
	if opts.Since != "" {
		args["since"] = opts.Since
	}
	if opts.EventType != "" {
		args["type"] = opts.EventType
	}
	if opts.Wait != "" {
		args["wait"] = opts.Wait
	}
	if opts.Limit > 0 {
		args["limit"] = opts.Limit
	}

	var resp protocol.OastPollResponse
	if err := c.CallToolJSON(ctx, "oast_poll", args, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// OastGet calls oast_get and returns full event data.
func (c *Client) OastGet(ctx context.Context, oastID, eventID string) (*protocol.OastGetResponse, error) {
	args := map[string]interface{}{
		"oast_id":  oastID,
		"event_id": eventID,
	}

	var resp protocol.OastGetResponse
	if err := c.CallToolJSON(ctx, "oast_get", args, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// OastList calls oast_list and returns sessions.
func (c *Client) OastList(ctx context.Context, limit int) (*protocol.OastListResponse, error) {
	args := make(map[string]interface{})
	if limit > 0 {
		args["limit"] = limit
	}

	var resp protocol.OastListResponse
	if err := c.CallToolJSON(ctx, "oast_list", args, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// OastDelete calls oast_delete.
func (c *Client) OastDelete(ctx context.Context, oastID string) error {
	_, err := c.CallTool(ctx, "oast_delete", map[string]interface{}{"oast_id": oastID})
	return err
}

// CrawlCreate calls crawl_create and returns the session.
func (c *Client) CrawlCreate(ctx context.Context, opts CrawlCreateOpts) (*protocol.CrawlCreateResponse, error) {
	args := make(map[string]interface{})
	if opts.Label != "" {
		args["label"] = opts.Label
	}
	if opts.SeedURLs != "" {
		args["seed_urls"] = opts.SeedURLs
	}
	if opts.SeedFlows != "" {
		args["seed_flows"] = opts.SeedFlows
	}
	if opts.Domains != "" {
		args["domains"] = opts.Domains
	}
	if len(opts.Headers) > 0 {
		args["headers"] = opts.Headers
	}
	if opts.MaxDepth > 0 {
		args["max_depth"] = opts.MaxDepth
	}
	if opts.MaxRequests > 0 {
		args["max_requests"] = opts.MaxRequests
	}
	if opts.Delay != "" {
		args["delay"] = opts.Delay
	}
	if opts.Parallelism > 0 {
		args["parallelism"] = opts.Parallelism
	}
	if opts.SubmitForms {
		args["submit_forms"] = opts.SubmitForms
	}
	if opts.IgnoreRobots {
		args["ignore_robots"] = opts.IgnoreRobots
	}

	var resp protocol.CrawlCreateResponse
	if err := c.CallToolJSON(ctx, "crawl_create", args, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// CrawlSeed calls crawl_seed to add seeds to a session.
func (c *Client) CrawlSeed(ctx context.Context, sessionID string, seedURLs, seedFlows string) (*protocol.CrawlSeedResponse, error) {
	args := map[string]interface{}{
		"session_id": sessionID,
	}
	if seedURLs != "" {
		args["seed_urls"] = seedURLs
	}
	if seedFlows != "" {
		args["seed_flows"] = seedFlows
	}

	var resp protocol.CrawlSeedResponse
	if err := c.CallToolJSON(ctx, "crawl_seed", args, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// CrawlStatus calls crawl_status and returns session status.
func (c *Client) CrawlStatus(ctx context.Context, sessionID string) (*protocol.CrawlStatusResponse, error) {
	var resp protocol.CrawlStatusResponse
	if err := c.CallToolJSON(ctx, "crawl_status", map[string]interface{}{"session_id": sessionID}, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// CrawlPoll calls crawl_poll and returns summary, flows, forms, or errors.
func (c *Client) CrawlPoll(ctx context.Context, sessionID string, opts CrawlPollOpts) (*protocol.CrawlPollResponse, error) {
	args := map[string]interface{}{
		"session_id": sessionID,
	}
	if opts.OutputMode != "" {
		args["output_mode"] = opts.OutputMode
	}
	if opts.Host != "" {
		args["host"] = opts.Host
	}
	if opts.Path != "" {
		args["path"] = opts.Path
	}
	if opts.Method != "" {
		args["method"] = opts.Method
	}
	if opts.Status != "" {
		args["status"] = opts.Status
	}
	if opts.SearchHeader != "" {
		args["search_header"] = opts.SearchHeader
	}
	if opts.SearchBody != "" {
		args["search_body"] = opts.SearchBody
	}
	if opts.ExcludeHost != "" {
		args["exclude_host"] = opts.ExcludeHost
	}
	if opts.ExcludePath != "" {
		args["exclude_path"] = opts.ExcludePath
	}
	if opts.Since != "" {
		args["since"] = opts.Since
	}
	if opts.Limit > 0 {
		args["limit"] = opts.Limit
	}
	if opts.Offset > 0 {
		args["offset"] = opts.Offset
	}

	var resp protocol.CrawlPollResponse
	if err := c.CallToolJSON(ctx, "crawl_poll", args, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// CrawlSessions calls crawl_sessions and returns all sessions.
func (c *Client) CrawlSessions(ctx context.Context, limit int) (*protocol.CrawlSessionsResponse, error) {
	args := make(map[string]interface{})
	if limit > 0 {
		args["limit"] = limit
	}

	var resp protocol.CrawlSessionsResponse
	if err := c.CallToolJSON(ctx, "crawl_sessions", args, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// CrawlStop calls crawl_stop to stop a session.
func (c *Client) CrawlStop(ctx context.Context, sessionID string) error {
	_, err := c.CallTool(ctx, "crawl_stop", map[string]interface{}{"session_id": sessionID})
	return err
}

// DiffFlow calls diff_flow and returns the structured diff.
func (c *Client) DiffFlow(ctx context.Context, opts DiffFlowOpts) (*protocol.DiffFlowResponse, error) {
	args := map[string]interface{}{
		"flow_a": opts.FlowA,
		"flow_b": opts.FlowB,
		"scope":  opts.Scope,
	}
	if opts.MaxDiffLines > 0 {
		args["max_diff_lines"] = opts.MaxDiffLines
	}

	var resp protocol.DiffFlowResponse
	if err := c.CallToolJSON(ctx, "diff_flow", args, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// CrawlGet calls crawl_get and returns full flow data.
func (c *Client) CrawlGet(ctx context.Context, flowID string, opts CrawlGetOpts) (*protocol.CrawlGetResponse, error) {
	args := map[string]interface{}{"flow_id": flowID}
	if opts.FullBody {
		args["full_body"] = true
	}
	if opts.Scope != "" {
		args["scope"] = opts.Scope
	}
	if opts.Pattern != "" {
		args["pattern"] = opts.Pattern
	}
	var resp protocol.CrawlGetResponse
	if err := c.CallToolJSON(ctx, "crawl_get", args, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// FindReflected calls find_reflected and returns detected reflections.
func (c *Client) FindReflected(ctx context.Context, flowID string) (*protocol.FindReflectedResponse, error) {
	args := map[string]interface{}{"flow_id": flowID}
	var resp protocol.FindReflectedResponse
	if err := c.CallToolJSON(ctx, "find_reflected", args, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}
