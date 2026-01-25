package service

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	mcpclient "github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Unit tests for MCP server functionality using mock backends.
// Integration tests that require Burp Suite are in integration_test.go.

// setupMCPServerWithMock creates an MCP server with mock backends for unit testing.
func setupMCPServerWithMock(t *testing.T) (*Server, *mcpclient.Client, *TestMCPServer, *mockOastBackend, *mockCrawlerBackend) {
	t.Helper()

	mockMCP := NewTestMCPServer(t)
	mockOast := newMockOastBackend()
	mockCrawler := newMockCrawlerBackend()

	srv, err := NewServer(MCPServerFlags{
		BurpMCPURL:   mockMCP.URL(),
		MCPPort:      0, // Let OS pick a port
		WorkflowMode: WorkflowModeNone,
	}, nil, mockOast, mockCrawler)
	require.NoError(t, err)

	serverErr := make(chan error, 1)
	go func() {
		serverErr <- srv.Run(t.Context())
	}()
	srv.WaitTillStarted()

	require.NotNil(t, srv.mcpServer, "MCP server should be started")

	// Use in-process client for reliable testing
	mcpClient, err := mcpclient.NewInProcessClient(srv.mcpServer.server)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	_, err = mcpClient.Initialize(ctx, mcp.InitializeRequest{
		Params: mcp.InitializeParams{
			ClientInfo: mcp.Implementation{
				Name:    "sectool-test",
				Version: "1.0.0",
			},
			ProtocolVersion: mcp.LATEST_PROTOCOL_VERSION,
		},
	})
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = mcpClient.Close()
		srv.RequestShutdown()
		<-serverErr
	})

	return srv, mcpClient, mockMCP, mockOast, mockCrawler
}

func TestMCP_ListTools(t *testing.T) {
	t.Parallel()

	_, mcpClient, _, _, _ := setupMCPServerWithMock(t)

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	result, err := mcpClient.ListTools(ctx, mcp.ListToolsRequest{})
	require.NoError(t, err)

	expectedTools := []string{
		"proxy_poll",
		"proxy_get",
		"proxy_rule_list",
		"proxy_rule_add",
		"proxy_rule_update",
		"proxy_rule_delete",
		"replay_send",
		"replay_get",
		"request_send",
		"oast_create",
		"oast_poll",
		"oast_get",
		"oast_list",
		"oast_delete",
		"encode_url",
		"encode_base64",
		"encode_html",
		"crawl_create",
		"crawl_seed",
		"crawl_status",
		"crawl_poll",
		"crawl_get",
		"crawl_sessions",
		"crawl_stop",
	}

	toolNames := make([]string, len(result.Tools))
	for i, tool := range result.Tools {
		toolNames[i] = tool.Name
	}

	for _, expected := range expectedTools {
		assert.Contains(t, toolNames, expected)
	}
}

const sinceLast = "last"

type mockOastBackend struct {
	sessions map[string]*OastSessionInfo
	byLabel  map[string]string
	events   map[string][]OastEventInfo
}

func newMockOastBackend() *mockOastBackend {
	return &mockOastBackend{
		sessions: make(map[string]*OastSessionInfo),
		byLabel:  make(map[string]string),
		events:   make(map[string][]OastEventInfo),
	}
}

func (b *mockOastBackend) CreateSession(ctx context.Context, label string) (*OastSessionInfo, error) {
	if label != "" {
		if _, ok := b.byLabel[label]; ok {
			return nil, ErrLabelExists
		}
	}
	id := "oast-test-" + time.Now().UTC().Format("150405.000000000")
	info := &OastSessionInfo{
		ID:        id,
		Domain:    id + ".test.invalid",
		Label:     label,
		CreatedAt: time.Now(),
	}
	b.sessions[id] = info
	if label != "" {
		b.byLabel[label] = id
	}
	return info, nil
}

func (b *mockOastBackend) PollSession(ctx context.Context, idOrDomain string, since string, eventType string, wait time.Duration, limit int) (*OastPollResultInfo, error) {
	id, err := b.resolveID(idOrDomain)
	if err != nil {
		return nil, err
	}
	events := b.events[id]
	if len(events) == 0 {
		return &OastPollResultInfo{Events: nil}, nil
	}

	start := 0
	if since != "" && since != sinceLast {
		for i, e := range events {
			if e.ID == since {
				start = i + 1
				break
			}
		}
	}

	filtered := make([]OastEventInfo, 0, len(events))
	for i := start; i < len(events); i++ {
		ev := events[i]
		if eventType != "" && ev.Type != eventType {
			continue
		}
		filtered = append(filtered, ev)
	}

	if limit > 0 && len(filtered) > limit {
		filtered = filtered[:limit]
	}

	return &OastPollResultInfo{Events: filtered}, nil
}

func (b *mockOastBackend) GetEvent(ctx context.Context, idOrDomain string, eventID string) (*OastEventInfo, error) {
	id, err := b.resolveID(idOrDomain)
	if err != nil {
		return nil, err
	}
	for _, ev := range b.events[id] {
		if ev.ID == eventID {
			e := ev
			return &e, nil
		}
	}
	return nil, ErrNotFound
}

func (b *mockOastBackend) ListSessions(ctx context.Context) ([]OastSessionInfo, error) {
	sessions := make([]OastSessionInfo, 0, len(b.sessions))
	for _, sess := range b.sessions {
		sessions = append(sessions, *sess)
	}
	return sessions, nil
}

func (b *mockOastBackend) DeleteSession(ctx context.Context, idOrDomain string) error {
	id, err := b.resolveID(idOrDomain)
	if err != nil {
		return err
	}
	sess := b.sessions[id]
	if sess.Label != "" {
		delete(b.byLabel, sess.Label)
	}
	delete(b.sessions, id)
	delete(b.events, id)
	return nil
}

func (b *mockOastBackend) Close() error {
	b.sessions = make(map[string]*OastSessionInfo)
	b.byLabel = make(map[string]string)
	b.events = make(map[string][]OastEventInfo)
	return nil
}

func (b *mockOastBackend) resolveID(idOrDomain string) (string, error) {
	if idOrDomain == "" {
		return "", ErrNotFound
	}
	if _, ok := b.sessions[idOrDomain]; ok {
		return idOrDomain, nil
	}
	for id, sess := range b.sessions {
		if sess.Domain == idOrDomain {
			return id, nil
		}
	}
	if id, ok := b.byLabel[idOrDomain]; ok {
		return id, nil
	}
	return "", ErrNotFound
}

type mockCrawlerBackend struct {
	sessions map[string]*CrawlSessionInfo
	byLabel  map[string]string
	status   map[string]*CrawlStatus
	flows    map[string]*CrawlFlow
	forms    map[string][]DiscoveredForm
	errors   map[string][]CrawlError
}

func newMockCrawlerBackend() *mockCrawlerBackend {
	return &mockCrawlerBackend{
		sessions: make(map[string]*CrawlSessionInfo),
		byLabel:  make(map[string]string),
		status:   make(map[string]*CrawlStatus),
		flows:    make(map[string]*CrawlFlow),
		forms:    make(map[string][]DiscoveredForm),
		errors:   make(map[string][]CrawlError),
	}
}

func (b *mockCrawlerBackend) CreateSession(ctx context.Context, opts CrawlOptions) (*CrawlSessionInfo, error) {
	if len(opts.Seeds) == 0 {
		return nil, errors.New("no valid seeds")
	}
	if opts.Label != "" {
		if _, ok := b.byLabel[opts.Label]; ok {
			return nil, ErrLabelExists
		}
	}
	id := "crawl-test-" + time.Now().UTC().Format("150405.000000000")
	info := &CrawlSessionInfo{
		ID:        id,
		Label:     opts.Label,
		State:     "running",
		CreatedAt: time.Now(),
	}
	b.sessions[id] = info
	if opts.Label != "" {
		b.byLabel[opts.Label] = id
	}
	b.status[id] = &CrawlStatus{
		State:        "running",
		URLsQueued:   len(opts.Seeds),
		LastActivity: time.Now(),
	}
	return info, nil
}

func (b *mockCrawlerBackend) AddSeeds(ctx context.Context, sessionID string, seeds []CrawlSeed) error {
	sess, err := b.resolveSession(sessionID)
	if err != nil {
		return err
	}
	if sess.State != "running" {
		return fmt.Errorf("session %s is not running (state: %s)", sessionID, sess.State)
	}
	if status := b.status[sess.ID]; status != nil {
		status.URLsQueued += len(seeds)
		status.LastActivity = time.Now()
	}
	return nil
}

func (b *mockCrawlerBackend) GetStatus(ctx context.Context, sessionID string) (*CrawlStatus, error) {
	sess, err := b.resolveSession(sessionID)
	if err != nil {
		return nil, err
	}
	status := b.status[sess.ID]
	if status == nil {
		return nil, ErrNotFound
	}
	copy := *status
	copy.Duration = time.Since(sess.CreatedAt)
	return &copy, nil
}

func (b *mockCrawlerBackend) ListFlows(ctx context.Context, sessionID string, opts CrawlListOptions) ([]CrawlFlow, error) {
	sess, err := b.resolveSession(sessionID)
	if err != nil {
		return nil, err
	}

	flows := make([]CrawlFlow, 0, len(b.flows))
	for _, flow := range b.flows {
		if flow.SessionID != sess.ID {
			continue
		}
		flows = append(flows, *flow)
	}

	if opts.Offset > 0 && opts.Offset < len(flows) {
		flows = flows[opts.Offset:]
	} else if opts.Offset >= len(flows) {
		flows = nil
	}

	if opts.Limit > 0 && len(flows) > opts.Limit {
		flows = flows[:opts.Limit]
	}

	return flows, nil
}

func (b *mockCrawlerBackend) ListForms(ctx context.Context, sessionID string, limit int) ([]DiscoveredForm, error) {
	sess, err := b.resolveSession(sessionID)
	if err != nil {
		return nil, err
	}
	forms := b.forms[sess.ID]
	if limit > 0 && len(forms) > limit {
		forms = forms[:limit]
	}
	return forms, nil
}

func (b *mockCrawlerBackend) ListErrors(ctx context.Context, sessionID string, limit int) ([]CrawlError, error) {
	sess, err := b.resolveSession(sessionID)
	if err != nil {
		return nil, err
	}
	errs := b.errors[sess.ID]
	if limit > 0 && len(errs) > limit {
		errs = errs[:limit]
	}
	return errs, nil
}

func (b *mockCrawlerBackend) GetFlow(ctx context.Context, flowID string) (*CrawlFlow, error) {
	flow, ok := b.flows[flowID]
	if !ok {
		return nil, ErrNotFound
	}
	return flow, nil
}

func (b *mockCrawlerBackend) StopSession(ctx context.Context, sessionID string) error {
	sess, err := b.resolveSession(sessionID)
	if err != nil {
		return err
	}
	sess.State = "stopped"
	if status := b.status[sess.ID]; status != nil {
		status.State = "stopped"
		status.LastActivity = time.Now()
	}
	return nil
}

func (b *mockCrawlerBackend) ListSessions(ctx context.Context, limit int) ([]CrawlSessionInfo, error) {
	sessions := make([]CrawlSessionInfo, 0, len(b.sessions))
	for _, sess := range b.sessions {
		sessions = append(sessions, *sess)
	}
	if limit > 0 && len(sessions) > limit {
		sessions = sessions[:limit]
	}
	return sessions, nil
}

func (b *mockCrawlerBackend) Close() error {
	b.sessions = make(map[string]*CrawlSessionInfo)
	b.byLabel = make(map[string]string)
	b.status = make(map[string]*CrawlStatus)
	b.flows = make(map[string]*CrawlFlow)
	b.forms = make(map[string][]DiscoveredForm)
	b.errors = make(map[string][]CrawlError)
	return nil
}

func (b *mockCrawlerBackend) AddFlow(sessionID string, flow CrawlFlow) error {
	sess, err := b.resolveSession(sessionID)
	if err != nil {
		return err
	}
	flow.SessionID = sess.ID
	b.flows[flow.ID] = &flow
	if status := b.status[sess.ID]; status != nil {
		status.URLsVisited++
		status.LastActivity = time.Now()
	}
	return nil
}

func (b *mockCrawlerBackend) AddForm(sessionID string, form DiscoveredForm) error {
	sess, err := b.resolveSession(sessionID)
	if err != nil {
		return err
	}
	b.forms[sess.ID] = append(b.forms[sess.ID], form)
	if status := b.status[sess.ID]; status != nil {
		status.FormsDiscovered++
		status.LastActivity = time.Now()
	}
	return nil
}

func (b *mockCrawlerBackend) AddError(sessionID string, crawlErr CrawlError) error {
	sess, err := b.resolveSession(sessionID)
	if err != nil {
		return err
	}
	b.errors[sess.ID] = append(b.errors[sess.ID], crawlErr)
	if status := b.status[sess.ID]; status != nil {
		status.URLsErrored++
		status.LastActivity = time.Now()
	}
	return nil
}

func (b *mockCrawlerBackend) resolveSession(idOrLabel string) (*CrawlSessionInfo, error) {
	id := idOrLabel
	if mapped, ok := b.byLabel[idOrLabel]; ok {
		id = mapped
	}
	sess, ok := b.sessions[id]
	if !ok {
		return nil, ErrNotFound
	}
	return sess, nil
}
