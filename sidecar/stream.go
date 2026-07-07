package sidecar

import "github.com/go-appsec/toolbox/sidecar/wire"

// CloseStream proactively closes an open stream (client-facing or a dialed
// upstream). It is the companion to the stream events delivered to a Handler.
func (c *Conn) CloseStream(streamID, reason string) error {
	return c.peer.Notify(wire.MethodCloseStream, wire.StreamEndedParams{StreamID: streamID, Reason: reason})
}

// StreamWrite proactively writes bytes to an open stream without a triggering
// event, for protocol keepalives and other timer-driven output. Ordinary data
// belongs in the writes returned from a stream event, which preserve ordering.
func (c *Conn) StreamWrite(streamID string, data []byte) error {
	return c.peer.Notify(wire.MethodStreamWrite, wire.StreamWriteParams{StreamID: streamID, Data: data})
}

// Forward builds the writes for a stream event Response that send data out a
// paired stream, e.g. a client-stream message forwarded to its upstream stream
// and vice-versa.
func Forward(toStreamID string, data []byte) []wire.StreamWrite {
	return []wire.StreamWrite{{StreamID: toStreamID, Data: data}}
}
