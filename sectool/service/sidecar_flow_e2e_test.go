//go:build unix

package service

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/toolbox/sectool/mcpclient"
	"github.com/go-appsec/toolbox/sectool/protocol"
	"github.com/go-appsec/toolbox/sectool/service/proxy"
	scsidecar "github.com/go-appsec/toolbox/sectool/service/proxy/protocol/sidecar"
	"github.com/go-appsec/toolbox/sectool/service/store"
	"github.com/go-appsec/toolbox/sidecar"
	"github.com/go-appsec/toolbox/sidecar/wire"
)

// flowIDs extracts the flow_id of each returned flow.
func flowIDs(flows []protocol.FlowEntry) []string {
	out := make([]string, len(flows))
	for i, f := range flows {
		out[i] = f.FlowID
	}
	return out
}

// TestSidecarFlowEmissionE2E drives the sidecar SDK against a live native backend
// over the IPC socket, emitting every flow shape, then reads them back through the
// real MCP tools (proxy_poll/flow_get/diff_flow) and core_query.
func TestSidecarFlowEmissionE2E(t *testing.T) {
	const adapterName = "custom-sidecar"
	instanceID := uuid.NewString()

	socket := filepath.Join(t.TempDir(), "sidecar.sock")
	backend, err := NewNativeProxyBackend(0, t.TempDir(), 10*1024*1024, store.MemProvider, proxy.TimeoutConfig{})
	require.NoError(t, err)

	srv, err := NewServer(MCPServerFlags{
		MCPPort:      0,
		WorkflowMode: protocol.WorkflowModeNone,
		ConfigPath:   filepath.Join(t.TempDir(), "config.json"),
	}, backend, newMockOastBackend(), newMockCrawlerBackend())
	require.NoError(t, err)
	srv.SetQuietLogging()

	// Enable sidecars with the server itself as the core_query dispatcher, then
	// start the backend (proxy + sidecar listener) and the MCP server.
	require.NoError(t, backend.EnableSidecars(scsidecar.Config{Socket: socket, NativeProxyPort: 0}, srv, srv.replayHistoryStore))
	go func() { _ = backend.Serve() }()

	serverErr := make(chan error, 1)
	go func() { serverErr <- srv.Run(t.Context()) }()
	srv.WaitTillStarted()
	t.Cleanup(func() {
		srv.RequestShutdown()
		<-serverErr
	})

	mcpClient, err := mcpclient.Connect(t.Context(), "http://"+srv.mcpServer.Addr()+"/mcp")
	require.NoError(t, err)
	t.Cleanup(func() { _ = mcpClient.Close() })

	conn, err := sidecar.Dial(socket, sidecar.Registration{
		Name:            adapterName,
		Protocols:       []string{"custom/1"},
		InstanceID:      instanceID,
		ProtocolVersion: wire.ProtocolVersion{Major: wire.VersionMajor, Minor: wire.VersionMinor},
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	ctx := t.Context()

	host := []wire.Header{{Name: "Host", Value: "unit.test"}}

	// 1. Plain request/response.
	plainID, err := conn.PushFlow(ctx, wire.Flow{
		ProtocolTag: "custom/1.req",
		Request:     &wire.FlowMessage{Method: "GET", Path: "/thing", Headers: host},
		Response:    &wire.FlowMessage{StatusCode: 200, Headers: []wire.Header{{Name: "Content-Type", Value: "application/json"}}, Body: []byte(`{"ok":true}`)},
	})
	require.NoError(t, err)

	// 2. Two-phase: request first, response attached later under the same id.
	twoPhaseID, err := conn.PushFlow(ctx, wire.Flow{
		ProtocolTag: "custom/1.req",
		Request:     &wire.FlowMessage{Method: "POST", Path: "/submit", Headers: host},
	})
	require.NoError(t, err)
	require.NoError(t, conn.CompleteFlow(ctx, twoPhaseID, &wire.FlowMessage{StatusCode: 201}, time.Now()))

	// 3. Stream: parent + ordered children + close.
	streamID, err := conn.PushFlow(ctx, wire.Flow{
		ProtocolTag: "custom/1.stream",
		Request:     &wire.FlowMessage{Method: "STREAM", Path: "/events", Headers: host},
	})
	require.NoError(t, err)
	childPayloads := []string{"one", "two", "three"}
	childIDs := make([]string, 0, len(childPayloads))
	for _, payload := range childPayloads {
		cid, cerr := conn.PushFlow(ctx, wire.Flow{
			ProtocolTag:  "custom/1.chunk",
			ParentFlowID: streamID,
			Direction:    "server_to_client",
			Request:      &wire.FlowMessage{Method: "CHUNK", Body: []byte(payload)},
		})
		require.NoError(t, cerr)
		childIDs = append(childIDs, cid)
	}
	require.NoError(t, conn.CompleteFlow(ctx, streamID, &wire.FlowMessage{StatusCode: 200}, time.Now()))

	// 4. Session/tunnel envelope with a nested child.
	tunnelID, err := conn.PushFlow(ctx, wire.Flow{
		ProtocolTag: "custom.tunnel",
		Direction:   "bidirectional",
		Request:     &wire.FlowMessage{Method: "TUNNEL", Path: "/custom/tunnel/1", Headers: []wire.Header{{Name: "Peer", Value: "abcd"}}},
	})
	require.NoError(t, err)
	_, err = conn.PushFlow(ctx, wire.Flow{
		ProtocolTag:  "custom.tunnel.msg",
		ParentFlowID: tunnelID,
		Direction:    "client_to_server",
		Request:      &wire.FlowMessage{Method: "MSG", Body: []byte("inner")},
	})
	require.NoError(t, err)

	// 5. Flow carrying body_raw/body_codec (logical Body differs from the wire form).
	rawID, err := conn.PushFlow(ctx, wire.Flow{
		ProtocolTag: "custom/1.bin",
		Request:     &wire.FlowMessage{Method: "GET", Path: "/bin", Headers: host},
		Response: &wire.FlowMessage{
			StatusCode: 200,
			Headers:    []wire.Header{{Name: "Content-Type", Value: "application/json"}},
			Body:       []byte(`{"decoded":1}`),
			BodyRaw:    []byte{0x08, 0x96, 0x01},
			BodyCodec:  &wire.BodyCodec{Transforms: []string{"protobuf"}, ContentType: "application/json"},
		},
	})
	require.NoError(t, err)

	// 6. Flow whose request parameter is reflected in the response body.
	reflectID, err := conn.PushFlow(ctx, wire.Flow{
		ProtocolTag: "custom/1.req",
		Request:     &wire.FlowMessage{Method: "GET", Path: "/search?q=reflectme123", Headers: host},
		Response:    &wire.FlowMessage{StatusCode: 200, Headers: []wire.Header{{Name: "Content-Type", Value: "text/html"}}, Body: []byte("<p>results for reflectme123</p>")},
	})
	require.NoError(t, err)

	// 7. Mutated flow carrying sidecar-authored audit annotations (captured/mutated pairing).
	mutatedID, err := conn.PushFlow(ctx, wire.Flow{
		ProtocolTag: "custom/1.mutated",
		Request:     &wire.FlowMessage{Method: "POST", Path: "/mutated", Headers: host},
		Response:    &wire.FlowMessage{StatusCode: 200},
		Annotations: map[string]any{"phase": "mutated", "fired_rules": []any{"r1"}, "parent_flow_id": plainID},
	})
	require.NoError(t, err)

	t.Run("top_level_flows_filtered_by_adapter", func(t *testing.T) {
		resp, perr := mcpClient.ProxyPoll(ctx, mcpclient.ProxyPollOpts{OutputMode: "flows", Adapter: adapterName, Limit: 100})
		require.NoError(t, perr)
		got := flowIDs(resp.Flows)
		assert.ElementsMatch(t, []string{plainID, twoPhaseID, streamID, tunnelID, rawID, reflectID, mutatedID}, got)
		// Children are not surfaced in the top-level listing.
		assert.NotContains(t, got, childIDs[0])
	})

	t.Run("flow_get_surfaces_sidecar_annotations", func(t *testing.T) {
		got, gerr := mcpClient.FlowGet(ctx, mutatedID, mcpclient.FlowGetOpts{})
		require.NoError(t, gerr)
		assert.Equal(t, "mutated", got.Annotations["phase"])
		assert.Equal(t, plainID, got.Annotations["parent_flow_id"])
		// sectool attribution is a typed field, never mixed into the sidecar map.
		assert.NotContains(t, got.Annotations, "sidecar_instance_id")
		assert.Equal(t, instanceID, got.SidecarInstanceID)
	})

	t.Run("flow_get_omits_absent_annotations", func(t *testing.T) {
		got, gerr := mcpClient.FlowGet(ctx, plainID, mcpclient.FlowGetOpts{})
		require.NoError(t, gerr)
		assert.Empty(t, got.Annotations)
	})

	t.Run("proxy_poll_lists_annotations_and_attribution", func(t *testing.T) {
		resp, perr := mcpClient.ProxyPoll(ctx, mcpclient.ProxyPollOpts{OutputMode: "flows", ProtocolTag: "custom/1.mutated", Limit: 100})
		require.NoError(t, perr)
		require.Len(t, resp.Flows, 1)
		entry := resp.Flows[0]
		assert.Equal(t, "mutated", entry.Annotations["phase"])
		assert.Equal(t, instanceID, entry.SidecarInstanceID)
		assert.Equal(t, adapterName, entry.Adapter)
		assert.Equal(t, "custom/1.mutated", entry.ProtocolTag)
	})

	t.Run("search_body_list_carries_attribution", func(t *testing.T) {
		// full-text path (search_body) must carry the same attribution as the meta path
		resp, perr := mcpClient.ProxyPoll(ctx, mcpclient.ProxyPollOpts{OutputMode: "flows", SearchBody: "reflectme123", Limit: 100})
		require.NoError(t, perr)
		var entry *protocol.FlowEntry
		for i := range resp.Flows {
			if resp.Flows[i].FlowID == reflectID {
				entry = &resp.Flows[i]
			}
		}
		require.NotNil(t, entry)
		assert.Equal(t, adapterName, entry.Adapter)
		assert.Equal(t, instanceID, entry.SidecarInstanceID)
	})

	t.Run("find_reflected_on_adapter_flow", func(t *testing.T) {
		resp, rerr := mcpClient.FindReflected(ctx, reflectID)
		require.NoError(t, rerr)
		require.NotEmpty(t, resp.Reflections)
		assert.Equal(t, "reflectme123", resp.Reflections[0].Value)
	})

	t.Run("protocol_tag_filter", func(t *testing.T) {
		resp, perr := mcpClient.ProxyPoll(ctx, mcpclient.ProxyPollOpts{OutputMode: "flows", ProtocolTag: "custom/1.stream", Limit: 100})
		require.NoError(t, perr)
		assert.Equal(t, []string{streamID}, flowIDs(resp.Flows))
	})

	t.Run("stream_children_in_emission_order", func(t *testing.T) {
		resp, perr := mcpClient.ProxyPoll(ctx, mcpclient.ProxyPollOpts{OutputMode: "flows", ParentFlowID: streamID, Limit: 100})
		require.NoError(t, perr)
		assert.Equal(t, childIDs, flowIDs(resp.Flows))
	})

	t.Run("tunnel_child_nesting", func(t *testing.T) {
		resp, perr := mcpClient.ProxyPoll(ctx, mcpclient.ProxyPollOpts{OutputMode: "flows", ParentFlowID: tunnelID, Limit: 100})
		require.NoError(t, perr)
		require.Len(t, resp.Flows, 1)
		assert.Equal(t, "inner", string(mustChildBody(t, backend, resp.Flows[0].FlowID)))
	})

	t.Run("two_phase_response_attached", func(t *testing.T) {
		got, gerr := mcpClient.FlowGet(ctx, twoPhaseID, mcpclient.FlowGetOpts{})
		require.NoError(t, gerr)
		assert.Equal(t, 201, got.Status)
	})

	t.Run("body_and_body_raw_round_trip", func(t *testing.T) {
		// Tools operate on the logical Body.
		got, gerr := mcpClient.FlowGet(ctx, rawID, mcpclient.FlowGetOpts{})
		require.NoError(t, gerr)
		assert.Contains(t, got.RespBody, `"decoded":1`)
		// The wire form and codec are retained for replay.
		stored, ok := backend.server.History().Get(rawID)
		require.True(t, ok)
		assert.Equal(t, []byte{0x08, 0x96, 0x01}, stored.Response.BodyRaw)
		require.NotNil(t, stored.Response.BodyCodec)
		assert.Equal(t, []string{"protobuf"}, stored.Response.BodyCodec.Transforms)
	})

	t.Run("per_flow_attribution", func(t *testing.T) {
		stored, ok := backend.server.History().Get(plainID)
		require.True(t, ok)
		assert.Equal(t, adapterName, stored.Adapter)
		assert.Equal(t, instanceID, stored.SidecarInstanceID)
	})

	t.Run("diff_flow_on_adapter_flows", func(t *testing.T) {
		resp, derr := mcpClient.DiffFlow(ctx, mcpclient.DiffFlowOpts{FlowA: plainID, FlowB: rawID, Scope: "response_body"})
		require.NoError(t, derr)
		assert.False(t, resp.Same)
		require.NotNil(t, resp.Response)
	})

	t.Run("core_invoke_reads_and_writes", func(t *testing.T) {
		res, qerr := conn.CoreInvoke(ctx, "proxy_poll", map[string]any{"output_mode": "flows", "adapter": adapterName, "limit": 100})
		require.NoError(t, qerr)
		assert.False(t, res.IsError)
		assert.Contains(t, res.Content, plainID)

		// write tools are invocable via core_invoke (dispatched, not rejected)
		_, qerr = conn.CoreInvoke(ctx, "proxy_rule_add", map[string]any{
			"rule_type": "request_header", "match": "X-A", "replace": "X-B",
		})
		require.NoError(t, qerr)
	})
}

func mustChildBody(t *testing.T, backend *NativeProxyBackend, flowID string) []byte {
	t.Helper()
	flow, ok := backend.server.History().Get(flowID)
	require.True(t, ok)
	require.NotNil(t, flow.Request)
	return flow.Request.Body
}
