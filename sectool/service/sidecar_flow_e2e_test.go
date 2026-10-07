//go:build unix

package service

import (
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/toolbox/sectool/config"
	"github.com/go-appsec/toolbox/sectool/mcpclient"
	"github.com/go-appsec/toolbox/sectool/protocol"
	scsidecar "github.com/go-appsec/toolbox/sectool/service/proxy/protocol/sidecar"
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

// mustPush emits flow via the SDK conn, asserting it was captured, and returns the flow_id.
func mustPush(t *testing.T, conn *sidecar.Conn, flow wire.Flow) string {
	t.Helper()
	id, captured, err := conn.PushFlow(t.Context(), flow)
	require.NoError(t, err)
	require.True(t, captured)
	return id
}

// TestSidecarFlowEmissionE2E drives the sidecar SDK against a live native backend
// over the IPC socket, emitting every flow shape, then reads them back through the
// real MCP tools (proxy_poll/flow_get/diff_flow) and core_query.
func TestSidecarFlowEmissionE2E(t *testing.T) {
	t.Parallel()

	const adapterName = "custom-sidecar"
	instanceID := uuid.NewString()

	sb := startSidecarBackend(t, scsidecar.Config{})
	backend, mcpClient := sb.backend, sb.mcp

	conn := sb.dial(t, sidecar.Registration{
		Name:       adapterName,
		Protocols:  []string{"custom/1"},
		InstanceID: instanceID,
	})

	host := []wire.Header{{Name: "Host", Value: "unit.test"}}

	// 1. Plain request/response.
	plainID := mustPush(t, conn, wire.Flow{
		ProtocolTag: "custom/1.req",
		Request:     &wire.FlowMessage{Method: "GET", Path: "/thing", Headers: host},
		Response:    &wire.FlowMessage{StatusCode: 200, Headers: []wire.Header{{Name: "Content-Type", Value: "application/json"}}, Body: []byte(`{"ok":true}`)},
	})

	// 2. Two-phase: request first, response attached later under the same id.
	twoPhaseID := mustPush(t, conn, wire.Flow{
		ProtocolTag: "custom/1.req",
		Request:     &wire.FlowMessage{Method: "POST", Path: "/submit", Headers: host},
	})
	require.NoError(t, conn.CompleteFlow(t.Context(), twoPhaseID, &wire.FlowMessage{StatusCode: 201}, time.Now()))

	// 3. Stream: parent + ordered children + close.
	streamID := mustPush(t, conn, wire.Flow{
		ProtocolTag: "custom/1.stream",
		Request:     &wire.FlowMessage{Method: "STREAM", Path: "/events", Headers: host},
	})
	childPayloads := []string{"one", "two", "three"}
	childIDs := make([]string, 0, len(childPayloads))
	for _, payload := range childPayloads {
		childIDs = append(childIDs, mustPush(t, conn, wire.Flow{
			ProtocolTag:  "custom/1.chunk",
			ParentFlowID: streamID,
			Direction:    "server_to_client",
			Request:      &wire.FlowMessage{Method: "CHUNK", Body: []byte(payload)},
		}))
	}
	require.NoError(t, conn.CompleteFlow(t.Context(), streamID, &wire.FlowMessage{StatusCode: 200}, time.Now()))

	// 4. Session/tunnel envelope with a nested child.
	tunnelID := mustPush(t, conn, wire.Flow{
		ProtocolTag: "custom.tunnel",
		Direction:   "bidirectional",
		Request:     &wire.FlowMessage{Method: "TUNNEL", Path: "/custom/tunnel/1", Headers: []wire.Header{{Name: "Peer", Value: "abcd"}}},
	})
	mustPush(t, conn, wire.Flow{
		ProtocolTag:  "custom.tunnel.msg",
		ParentFlowID: tunnelID,
		Direction:    "client_to_server",
		Request:      &wire.FlowMessage{Method: "MSG", Body: []byte("inner")},
	})

	// 5. Flow carrying body_raw/body_codec (logical Body differs from the wire form).
	rawID := mustPush(t, conn, wire.Flow{
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

	// 6. Flow whose request parameter is reflected in the response body.
	reflectID := mustPush(t, conn, wire.Flow{
		ProtocolTag: "custom/1.req",
		Request:     &wire.FlowMessage{Method: "GET", Path: "/search?q=reflectme123", Headers: host},
		Response:    &wire.FlowMessage{StatusCode: 200, Headers: []wire.Header{{Name: "Content-Type", Value: "text/html"}}, Body: []byte("<p>results for reflectme123</p>")},
	})

	// 7. Mutated flow carrying sidecar-authored audit annotations (captured/mutated pairing).
	mutatedID := mustPush(t, conn, wire.Flow{
		ProtocolTag: "custom/1.mutated",
		Request:     &wire.FlowMessage{Method: "POST", Path: "/mutated", Headers: host},
		Response:    &wire.FlowMessage{StatusCode: 200},
		Annotations: map[string]any{"phase": "mutated", "fired_rules": []any{"r1"}, "parent_flow_id": plainID},
	})

	t.Run("top_level_flows_filtered_by_adapter", func(t *testing.T) {
		resp, perr := mcpClient.ProxyPoll(t.Context(), mcpclient.ProxyPollOpts{OutputMode: "flows", Adapter: adapterName, Limit: 100})
		require.NoError(t, perr)
		got := flowIDs(resp.Flows)
		assert.ElementsMatch(t, []string{plainID, twoPhaseID, streamID, tunnelID, rawID, reflectID, mutatedID}, got)
		// Children are not surfaced in the top-level listing.
		assert.NotContains(t, got, childIDs[0])
	})

	t.Run("flow_get_surfaces_sidecar_annotations", func(t *testing.T) {
		got, gerr := mcpClient.FlowGet(t.Context(), mutatedID, mcpclient.FlowGetOpts{})
		require.NoError(t, gerr)
		assert.Equal(t, "mutated", got.Annotations["phase"])
		assert.Equal(t, plainID, got.Annotations["parent_flow_id"])
		// sectool attribution is a typed field, never mixed into the sidecar map.
		assert.NotContains(t, got.Annotations, "sidecar_instance_id")
		assert.Equal(t, instanceID, got.SidecarInstanceID)
	})

	t.Run("flow_get_omits_absent_annotations", func(t *testing.T) {
		got, gerr := mcpClient.FlowGet(t.Context(), plainID, mcpclient.FlowGetOpts{})
		require.NoError(t, gerr)
		assert.Empty(t, got.Annotations)
	})

	t.Run("proxy_poll_lists_annotations_and_attribution", func(t *testing.T) {
		resp, perr := mcpClient.ProxyPoll(t.Context(), mcpclient.ProxyPollOpts{OutputMode: "flows", ProtocolTag: "custom/1.mutated", Limit: 100})
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
		resp, perr := mcpClient.ProxyPoll(t.Context(), mcpclient.ProxyPollOpts{OutputMode: "flows", SearchBody: "reflectme123", Limit: 100})
		require.NoError(t, perr)
		i := slices.IndexFunc(resp.Flows, func(f protocol.FlowEntry) bool { return f.FlowID == reflectID })
		require.GreaterOrEqual(t, i, 0)
		assert.Equal(t, adapterName, resp.Flows[i].Adapter)
		assert.Equal(t, instanceID, resp.Flows[i].SidecarInstanceID)
	})

	t.Run("find_reflected_on_adapter_flow", func(t *testing.T) {
		resp, rerr := mcpClient.FindReflected(t.Context(), reflectID)
		require.NoError(t, rerr)
		require.NotEmpty(t, resp.Reflections)
		assert.Equal(t, "reflectme123", resp.Reflections[0].Value)
	})

	t.Run("protocol_tag_filter", func(t *testing.T) {
		resp, perr := mcpClient.ProxyPoll(t.Context(), mcpclient.ProxyPollOpts{OutputMode: "flows", ProtocolTag: "custom/1.stream", Limit: 100})
		require.NoError(t, perr)
		assert.Equal(t, []string{streamID}, flowIDs(resp.Flows))
	})

	t.Run("stream_children_in_emission_order", func(t *testing.T) {
		resp, perr := mcpClient.ProxyPoll(t.Context(), mcpclient.ProxyPollOpts{OutputMode: "flows", ParentFlowID: streamID, Limit: 100})
		require.NoError(t, perr)
		assert.Equal(t, childIDs, flowIDs(resp.Flows))
	})

	t.Run("tunnel_child_nesting", func(t *testing.T) {
		resp, perr := mcpClient.ProxyPoll(t.Context(), mcpclient.ProxyPollOpts{OutputMode: "flows", ParentFlowID: tunnelID, Limit: 100})
		require.NoError(t, perr)
		require.Len(t, resp.Flows, 1)
		assert.Equal(t, "inner", string(mustChildBody(t, backend, resp.Flows[0].FlowID)))
	})

	t.Run("two_phase_response_attached", func(t *testing.T) {
		got, gerr := mcpClient.FlowGet(t.Context(), twoPhaseID, mcpclient.FlowGetOpts{})
		require.NoError(t, gerr)
		assert.Equal(t, 201, got.Status)
	})

	t.Run("body_and_body_raw_round_trip", func(t *testing.T) {
		// Tools operate on the logical Body.
		got, gerr := mcpClient.FlowGet(t.Context(), rawID, mcpclient.FlowGetOpts{})
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
		resp, derr := mcpClient.DiffFlow(t.Context(), mcpclient.DiffFlowOpts{FlowA: plainID, FlowB: rawID, Scope: "response_body"})
		require.NoError(t, derr)
		assert.False(t, resp.Same)
		require.NotNil(t, resp.Response)
	})

	t.Run("core_invoke_reads_and_writes", func(t *testing.T) {
		res, qerr := conn.CoreInvoke(t.Context(), "proxy_poll", map[string]any{"output_mode": "flows", "adapter": adapterName, "limit": 100})
		require.NoError(t, qerr)
		assert.False(t, res.IsError)
		assert.Contains(t, res.Content, plainID)

		// write tools are dispatched (not rejected) and take effect
		addRes, qerr := conn.CoreInvoke(t.Context(), "proxy_rule_add", map[string]any{
			"type": "request_header", "find": "X-A", "replace": "X-B",
		})
		require.NoError(t, qerr)
		require.False(t, addRes.IsError, addRes.Content)

		listRes, lerr := conn.CoreInvoke(t.Context(), "proxy_rule_list", map[string]any{})
		require.NoError(t, lerr)
		assert.Contains(t, listRes.Content, "X-B")
	})
}

func mustChildBody(t *testing.T, backend *NativeProxyBackend, flowID string) []byte {
	t.Helper()
	flow, ok := backend.server.History().Get(flowID)
	require.True(t, ok)
	require.NotNil(t, flow.Request)
	return flow.Request.Body
}

// TestSidecarPushFlowNotCapturedE2E drives a capture-filtered push through a real
// backend, asserting the SDK reports captured=false with an empty flow_id, the flow
// never reaches history, and CompleteFlow on the empty id is rejected locally.
func TestSidecarPushFlowNotCapturedE2E(t *testing.T) {
	t.Parallel()

	sb := startSidecarBackend(t, scsidecar.Config{})
	// the harness injects its backend, skipping the server's filter setup, so
	// install the default exclude-extensions filter directly
	filter, ferr := BuildCaptureFilter(config.DefaultConfig().Proxy)
	require.NoError(t, ferr)
	require.NotNil(t, filter)
	sb.backend.SetCaptureFilter(filter)

	conn := sb.dial(t, sidecar.Registration{Name: "filtered-sidecar"})

	filteredID, captured, err := conn.PushFlow(t.Context(), wire.Flow{
		ProtocolTag: "custom/1.img",
		Request:     &wire.FlowMessage{Method: "GET", Path: "/img.png", Headers: []wire.Header{{Name: "Host", Value: "unit.test"}}},
	})
	require.NoError(t, err)
	assert.False(t, captured)
	assert.Empty(t, filteredID)

	// CompleteFlow on the not-captured id must fail locally, not store a junk flow
	err = conn.CompleteFlow(t.Context(), filteredID, &wire.FlowMessage{StatusCode: 200}, time.Now())
	require.ErrorIs(t, err, sidecar.ErrEmptyFlowID)

	// a non-excluded path under the same backend is still captured normally
	keptID := mustPush(t, conn, wire.Flow{
		ProtocolTag: "custom/1.img",
		Request:     &wire.FlowMessage{Method: "GET", Path: "/page", Headers: []wire.Header{{Name: "Host", Value: "unit.test"}}},
	})
	_, ok := sb.backend.server.History().Get(keptID)
	require.True(t, ok)

	_, ok = sb.backend.server.History().Get(filteredID)
	assert.False(t, ok)
}
