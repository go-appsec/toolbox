//go:build unix

package service

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/toolbox/sectool/mcpclient"
	scsidecar "github.com/go-appsec/toolbox/sectool/service/proxy/protocol/sidecar"
	"github.com/go-appsec/toolbox/sidecar"
	"github.com/go-appsec/toolbox/sidecar/wire"
)

// replaySendHandler records the routed request and emits the result flow linked to
// the source, without setting the replay annotation (sectool must classify it).
type replaySendHandler struct {
	sidecar.BaseHandler
	t    *testing.T
	conn *sidecar.Conn
	got  chan wire.SidecarSendParams
}

func (h *replaySendHandler) OnSidecarSend(p wire.SidecarSendParams) (wire.SidecarSendResult, error) {
	h.got <- p
	id, _, err := h.conn.PushFlow(h.t.Context(), wire.Flow{
		ParentFlowID: p.FlowID,
		ProtocolTag:  "mqtt/3.publish",
		Request:      &wire.FlowMessage{Method: "PUBLISH", Path: "/topic"},
		Response:     &wire.FlowMessage{StatusCode: 202, Body: []byte("queued")},
	})
	if err != nil {
		return wire.SidecarSendResult{}, err
	}
	return wire.SidecarSendResult{
		NewFlowIDs: []string{id},
		Response:   &wire.FlowMessage{StatusCode: 202, Body: []byte("queued")},
	}, nil
}

// TestSidecarReplaySendE2E drives replay_send against a sidecar-owned flow and
// asserts it routes to the owning adapter's OnSidecarSend (with the source flow
// and built mutations) rather than the native HTTP send path.
func TestSidecarReplaySendE2E(t *testing.T) {
	t.Parallel()

	const adapterName = "mqtt"

	sb := startSidecarBackend(t, scsidecar.Config{})
	backend, srv, mcpClient := sb.backend, sb.srv, sb.mcp

	conn := sb.dial(t, sidecar.Registration{
		Name:      adapterName,
		Protocols: []string{"mqtt/3"},
	})

	// install up front: Serve's own install races the sidecar_send request below
	h := &replaySendHandler{t: t, conn: conn, got: make(chan wire.SidecarSendParams, 1)}
	conn.SetHandler(h)
	go func() { _ = conn.Serve(t.Context(), h) }()

	// The adapter owns a flow in history.
	flowID, _, err := conn.PushFlow(t.Context(), wire.Flow{
		ProtocolTag: "mqtt/3.publish",
		Request: &wire.FlowMessage{
			Method:  "PUBLISH",
			Path:    "/topic",
			Headers: []wire.Header{{Name: "Host", Value: "broker.test"}},
			Body:    []byte("{}"),
		},
	})
	require.NoError(t, err)

	resp, err := mcpClient.ReplaySend(t.Context(), mcpclient.ReplaySendOpts{
		FlowID:         flowID,
		SetHeaders:     []string{"X-New: 1"},
		Body:           "raw",
		StreamStrategy: "per_chunk",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.FlowID)
	assert.Equal(t, 202, resp.Status)
	assert.Contains(t, resp.RespPreview, "queued")

	// sectool auto-classified the un-annotated result into replay history
	entry, ok := srv.replayHistoryStore.Get(resp.FlowID)
	require.True(t, ok)
	assert.Equal(t, flowID, entry.SourceFlowID)
	_, inProxy := backend.server.History().Get(resp.FlowID)
	assert.False(t, inProxy)

	// The replay routed to the adapter with the source flow inline and the
	// built mutation list.
	select {
	case p := <-h.got:
		assert.Equal(t, flowID, p.FlowID)
		require.NotNil(t, p.Flow)
		assert.Equal(t, "per_chunk", p.StreamStrategy)
		ops := make([]string, 0, len(p.Mutations))
		for _, mu := range p.Mutations {
			ops = append(ops, mu.Op)
		}
		assert.Equal(t, []string{"set_header", "body"}, ops)
	case <-time.After(2 * time.Second):
		t.Fatal("sidecar_send was not routed to the adapter")
	}
}
