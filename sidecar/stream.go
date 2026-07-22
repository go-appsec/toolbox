package sidecar

import "github.com/go-appsec/toolbox/sidecar/wire"

// CloseStream proactively closes an open stream (client-facing or a dialed upstream).
// It closes after the writes already sent for that stream, or immediately when abort
// drops them. It is the companion to the stream events delivered to a Handler.
func (c *Conn) CloseStream(streamID, reason string, abort bool) error {
	return c.peer.Notify(wire.MethodCloseStream, wire.StreamEndedParams{StreamID: streamID, Reason: reason, Abort: abort})
}

// StreamWrite proactively writes bytes to an open stream without a triggering event,
// for keepalives and output produced by a synchronous state machine. Bytes reach the
// stream in send order, including against writes returned from stream events.
func (c *Conn) StreamWrite(streamID string, data []byte) error {
	return c.peer.Notify(wire.MethodStreamWrite, wire.StreamWriteParams{StreamID: streamID, Data: data})
}

// Forward builds the writes for a stream event Response that send data out a paired stream.
func Forward(toStreamID string, data []byte) []wire.StreamWrite {
	return []wire.StreamWrite{{StreamID: toStreamID, Data: data}}
}

// sendWrites emits a handler's writes as stream_write notifications so they share
// the ordered path with proactive writes, and replies naming the streams touched.
func (c *Conn) sendWrites(writes []wire.StreamWrite) (any, *wire.Error) {
	wroteTo := make([]string, 0, len(writes))
	for _, w := range writes {
		if err := c.peer.Notify(wire.MethodStreamWrite, wire.StreamWriteParams(w)); err != nil {
			return nil, wire.NewError(wire.CodeTransportInternal, "stream_write: "+err.Error())
		}
		wroteTo = append(wroteTo, w.StreamID)
	}
	return wire.StreamResult{WroteTo: wroteTo}, nil
}
