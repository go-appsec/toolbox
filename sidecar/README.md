# Sidecar SDK & Protocol

Build protocol adapters that integrate with sectool's capture, rule, replay, and analysis surface. Any protocol, MQTT, proprietary RPC, or custom binary framing, can present its traffic into sectool's unified flow timeline and reuse the existing toolset with full agent parity.

Two ways to implement an adapter:

- **[Go SDK](#go-sdk)** — the `sidecar` package handles registration, rule caching, and flow emission so your adapter focuses on parsing and sending protocol frames.
- **[JSON-RPC 2.0 wire protocol](#json-rpc-20-wire-protocol)** — sidecars can be written in any language; they just speak the length-prefixed JSON-RPC 2.0 contract over a local socket.

---

## Concepts

### Architecture

Sectool owns all sockets, client-facing and upstream. Bytes flow over the IPC connection as base64 encoded fields inside JSON-RPC 2.0 messages, keeping the contract portable across Linux, macOS, and Windows.

The captured representation maps to an HTTP-shaped envelope (`method`, `path`, `headers`, `body`) with an adapter-defined `protocol_tag` in the slot HTTP uses for its version. Every existing sectool tool (`flow_get`, `diff_flow`, `find_reflected`, `replay_send`, `notes_save`, …) then works on adapter flows without per-adapter schema reasoning.

#### Connection lifecycle

1. **Connect & register.** Sidecar dials the socket and sends a `register` request (see [register](#register-sidecar--sectool)). Sectool replies with the effective version, or rejects with `-33001` on version mismatch.
2. **Rule sync.** Rules arrive only through `sync_rules`, pushed at registration and on every change (see [sync_rules](#sync_rules-sectool--sidecar)).
3. **Capture.** Sidecar emits flows via `push_flow`; two-phase completion, streams, and sessions all use the same method (see [Flow model](#flow-model)).
4. **Data path.** For claimed connections, sectool drives `stream_open` then `stream_deliver`, awaiting each response before the next chunk; the sidecar sends outbound bytes as `stream_write` and names them in the response `wrote_to`, and may nest `dial_upstream`, `core_invoke`, or `push_flow` (see [stream_deliver](#stream_deliver-sectool--sidecar)).
5. **Heartbeat.** `ping` / `pong` keep the connection alive in both directions.
6. **Shutdown.** Sectool sends `shutdown`; the sidecar drains, emits final metrics, and closes.

### Transport

Sidecars connect to sectool over a local socket resolved from config:

| OS | Transport | Default address |
|----|-----------|-----------------|
| Unix (Linux, macOS) | Unix domain socket | `~/.sectool/sidecar.sock` |
| Windows | Loopback TCP (`127.0.0.1`) | auto-assigned port in config |

Override via the `--sidecar-socket <value>` CLI flag or the `sidecar_socket` field in `~/.sectool/config.json`. The network is inferred from shape: a `host:port` uses TCP, anything else uses a Unix domain socket. Sectool binds the address and an attached sidecar dials it, both resolving the same config value, so no custom configuration is needed.

### Versioning

The `protocol_version` (`{major, minor}`) gates the session during `register`. The Go SDK defaults to the toolbox release the sidecar was built against.

- **Major mismatch** → hard reject with `-33001` (`ErrVersionUnsupported`).
- **Minor ≤ sectool's minor** → accepted; session runs at the sidecar's minor.
- **Sidecar minor > sectool's minor** → rejected with `-33001`; update sectool.

### Flow model

A **Flow** is one logical exchange. It MAY carry a `request` side and a `response` side, each an envelope of `{method, path, query, status_code, status_text, headers, body}`. The envelope fields live inside the sub-objects; flow-level fields (`protocol_tag`, `direction`, `parent_flow_id`, timestamps, `annotations`) sit alongside.

- **Request/response** protocols populate both sides under one `flow_id`.
- **One-way messages** (tunnel envelopes, stream chunks, pub/sub frames) populate a single side and rely on `direction` (`client_to_server` | `server_to_client` | `bidirectional`).
- **Two-phase completion** — emit the request side first (sectool returns a `flow_id`), attach the response later by re-emitting with the same `flow_id`.
- **Streams and sessions** — a parent flow plus child flows that set `parent_flow_id`. Children are stored and replayed in emission order; sectool never reorders, so there is no per-chunk sequence number. A `direction=bidirectional`, `method=TUNNEL` parent is a session/tunnel envelope; its `flow_id` is the grouping key.
- **Non-decodable bodies** — when the wire form is not natively decodable by sectool (protobuf, custom framing), supply the logical `body` plus `body_raw` (verbatim wire bytes) and `body_codec` (the transform chain and content-type). Unmutated replay resends `body_raw`; a mutated body is re-encoded through `body_codec`.

### Capabilities

A sidecar declares which connection-handling seams it claims at registration. Each kind is a list (`early_claims`, `upgrade_claims`, `injection_targets`), so one registration can claim several protocol entry points:

- **`early_claim`** — claim TCP connections from accept on a port range, optionally gated by `magic_bytes_prefix`, `host_match`, `sni_match`, or a dynamic `probe`. With `tls.terminate`, sectool MitMs TLS and the sidecar receives the decrypted contents. `tls.cert` optionally declares additive SANs (`dns_names`, `ip_addresses`, `uris`, `emails`) and a legacy `common_name` to mint onto the terminated leaf, for clients that verify a name (or URI/SPIFFE identity) other than the SNI they dial. The declaration is purely additive; the leaf always retains the dialed name. A connection matching no claim falls through to the HTTP adapter.
- **`upgrade_claim`** — claim a byte stream after an HTTP upgrade (`http_101` or `connect`). Sectool captures the triggering request as a normal flow, synthesizes the upgrade response, and routes subsequent bytes to the sidecar; the captured request's `flow_id` and headers are surfaced on stream open.
- **`injection_target`** — declare the adapter can originate new outbound messages, enabling `replay_send` routing and cross-adapter `invoke_adapter`.

A sidecar with multiple claims routes an inbound stream on the protocol input `stream_open` carries — `host`/`path`/`request_headers` for an upgrade claim, `host` plus the opening `stream_deliver` bytes for an early claim.

Any sidecar may emit flows and apply pushed rules without declaring a capability. Conflicts (overlapping port ranges, ambiguous matchers, duplicate names) are rejected at registration time, naming both parties.

#### Early claim matching

An early claim is offered connections at two seams, and every matcher it declares is applied at both. An omitted matcher matches anything: an unset `port_range` (`{"low": 0, "high": 0}`) spans every port, and an empty `host_match` or `sni_match` matches any host or SNI.

| | raw accept | decrypted post-CONNECT stream |
| --- | --- | --- |
| `port_range` | the proxy's listen port | the CONNECT target port |
| `host_match` | not applicable | the CONNECT target host |
| `sni_match` | not applicable | the ClientHello SNI, for `tls.terminate` claims |
| `magic_bytes_prefix`, `probe` | applied | applied |

A `tls.terminate` claim gates termination itself: sectool MitMs a matching connection with its own CA and offers that claim the decrypted stream first. Every other claim sees the stream only if the terminating claim declines, and is still gated by its own matchers — a claim never receives traffic outside what it declared.

Claims rejected at registration:

- an early claim covering the native proxy port with no `magic_bytes_prefix`, `probe`, or `tls.terminate` — it would swallow all proxy traffic (`capability_conflict`)
- an invalid `port_range` (inverted or outside 1–65535), a `magic_bytes_prefix` that is not non-empty standard base64, a negative `probe_max_bytes`, an unknown `upgrade_signal`, or a pattern that is not valid RE2 (`registration_rejected`)

A raw claim and a `tls.terminate` claim occupy separate seams, so one registration may declare both for the plain and TLS forms of a protocol.

#### Upgrade claim matching

`host_pattern` and `path_pattern` are RE2 patterns matched against the whole value (compiled as `^(?:pattern)$`), so `app\.example\.com` matches only that host while `app.example.com` also matches `appXexample!com` — escape metacharacters for an exact match. An empty pattern matches anything, and `path_pattern` is matched against the path with any query string removed. An empty `upgrade_signal` means `http_101`, which additionally requires an `Upgrade` header on the request.

When two claims can match the same request, the more specific one wins: a literal pattern outranks a regex, which outranks an empty pattern. Two overlapping claims where neither is strictly more specific are rejected at registration.

### Mutation ownership

A flow's content is mutated by exactly one party: sectool itself for native HTTP/WS flows, or the sidecar that captured it for adapter-owned flows. Sectool never mutates a sidecar-owned flow's plaintext (it relays opaque/ciphertext bytes), so nothing outside the owner ever rewrites that flow.

As owner, a sidecar mutates through two mechanisms:

- **Hot path** — pushed rules applied inline as traffic flows (see [Rules](#rules)).
- **Replay / origination** — the ordered mutation ops carried on `sidecar_send` / `invoke_adapter`, applied when an agent re-sends or originates a message (see [Mutation operations](#mutation-operations)).

### Rules

Proxy rules are protocol-coupled, so a sidecar applies the rules relevant to its own flows; HTTP/WS traffic not delegated to a sidecar is handled by sectool. Sectool pushes the authoritative ordered rule list via `sync_rules`, one push at a time per sidecar and always carrying the current list; the sidecar replaces its local cache atomically and applies find/replace on its hot path, exactly as the native proxy does. Sectool filters the list per sidecar, sending only rules with an empty `adapter` scope or matching the sidecar's name.

---

## Go SDK

### Quick start

```go
package main

import (
    "context"
    "log"
    "os"
    "path/filepath"

    "github.com/go-appsec/toolbox/sidecar"
    "github.com/go-appsec/toolbox/sidecar/wire"
)

type myHandler struct{ sidecar.BaseHandler }

func (h *myHandler) OnStreamDeliver(p wire.StreamWriteParams) ([]wire.StreamWrite, error) {
    // Parse protocol frames from p.Data and emit flows...
    return nil, nil
}

func main() {
    reg := sidecar.Registration{
        Name:      "my-protocol",
        Protocols: []string{"myproto/1"},
        Capabilities: wire.Capabilities{
            EarlyClaims: []wire.EarlyClaim{{
                PortRange:        wire.PortRange{Low: 9443, High: 9443},
                MagicBytesPrefix: "bXlwcm90bw==", // base64 of magic bytes
            }},
        },
    }

    ctx := context.Background()
    home, _ := os.UserHomeDir()
    sock := filepath.Join(home, ".sectool", "sidecar.sock")
    conn, err := sidecar.Dial(ctx, sock, reg)
    if err != nil {
        log.Fatal(err)
    }
    defer conn.Close()

    log.Fatal(conn.Serve(ctx, &myHandler{}))
}
```

### Registration

`sidecar.Dial(ctx, addr, reg)` connects and registers, with the connect and handshake bounded by `ctx`. The `Registration` struct declares your adapter's identity and capabilities:

```go
reg := sidecar.Registration{
    Name:            "mqtt-adapter",
    ProtocolVersion: wire.ProtocolVersion{},       // zero defaults to the SDK's compiled contract version
    Protocols:       []string{"mqtt/3.1.1"},
    Capabilities:    wire.Capabilities{...},
    MCPTools:        []wire.MCPTool{...},           // optional custom MCP tools
}

conn, err := sidecar.Dial(ctx, addr, reg)
if errors.Is(err, sidecar.ErrVersionUnsupported) {
    // built against an incompatible toolbox (wrong major, or newer minor); rebuild against the running `sectool`
}
```

- **Name** — unique adapter identifier (cannot be `sectool`, the core process)
- **ProtocolVersion** — the gating `{major, minor}` contract version; leave zero to default to the SDK's compiled version
- **Protocols** — protocol identifiers the adapter provides
- **Capabilities** — connection-handling seams to claim (see [Capabilities](#capabilities))
- **MCPTools** — optional custom MCP tools the sidecar exposes to agents
- **InstanceID** — optional UUID for reconnect state recovery; **Resume** requests reattachment of in-flight flow metadata

### Serving

```go
err := conn.Serve(ctx, &myHandler{})
```

`Serve` blocks until context cancellation or remote close. Returns `ctx.Err()` on cancellation, `nil` on clean shutdown.

### Handler interface

Implement `sidecar.Handler` to receive inbound events. Embed `BaseHandler` for no-op defaults and override only what you need:

| Method | When called | Return |
|--------|-------------|--------|
| `OnShutdown(drainSeconds int)` | Sectool requests graceful close | — |
| `OnStreamOpen(params)` | A claimed stream opens (early or upgrade claim) | `[]wire.StreamWrite` for initial response bytes |
| `OnStreamDeliver(params)` | Inbound bytes arrive on a stream | `[]wire.StreamWrite` to write back (possibly to a different stream) |
| `OnStreamEnded(params)` | A stream closes (peer disconnect, scope policy, shutdown) | — |
| `OnClaimProbe(params)` | Probe-based early claim asks if the connection is this protocol | `(bool, error)`, true claims it |
| `OnSidecarSend(params)` | Agent replays or originates a message through this adapter | `(wire.SidecarSendResult, error)` |
| `OnInvokeTool(params)` | An MCP client calls one of the sidecar's registered tools | `(wire.InvokeToolResult, error)` |

#### Stream events

`OnStreamDeliver` receives raw transport bytes, not aligned to protocol frame boundaries. One frame may span several deliveries; several may arrive in one chunk. Use `sidecar.Reassembler` to buffer and extract complete frames:

```go
var reasm sidecar.Reassembler

func (h *myHandler) OnStreamDeliver(p wire.StreamWriteParams) ([]wire.StreamWrite, error) {
    reasm.Append(p.Data)
    for frame, ok := reasm.Next(h.splitFrame); ok; frame, ok = reasm.Next(h.splitFrame) {
        // Process complete frame...
    }
    return nil, nil
}

func (h *myHandler) splitFrame(buf []byte) (n int, ok bool) {
    // Return frame length and true when a complete frame is buffered.
}
```

The returned writes tell sectool what bytes to write back. A write may target a **different** `stream_id` than the event arrived on; that is how client data is forwarded upstream. The SDK sends them as `stream_write` so they share one ordered path with proactive `StreamWrite`, keeping a stream's bytes in send order. `sidecar.Forward(streamID, bytes)` builds a single-target writes slice:

```go
func (h *myHandler) OnStreamDeliver(p wire.StreamWriteParams) ([]wire.StreamWrite, error) {
    return sidecar.Forward(upstreamID, frameBytes), nil
}
```

### Emitting flows

#### PushFlow

Emit a captured exchange. Leave `flow_id` empty on first emission; sectool assigns it:

```go
flowID, err := conn.PushFlow(ctx, wire.Flow{
    ProtocolTag: "mqtt/3.1.1",
    Direction:   "client_to_server",
    Request: &wire.FlowMessage{
        Method:  "PUBLISH",
        Path:    "/sensors/temp",
        Headers: []wire.Header{{Name: "QoS", Value: "1"}},
        Body:    payload,
    },
})
```

#### Two-phase completion

Emit the request side first, then attach the response with the returned `flow_id` (see [Flow model](#flow-model)):

```go
flowID, _ := conn.PushFlow(ctx, wire.Flow{Request: req})
// Later:
conn.CompleteFlow(ctx, flowID, resp, time.Now())
```

#### Rule mutations

When a rule mutates a message on the hot path, store a single flow (the mutated one) via `PushFlow`, mirroring the native proxy. Do not emit a separate pre-mutation copy.

#### Streams and sessions

Use parent-child flows for long-lived exchanges (see [Flow model](#flow-model)):

```go
// Open stream (parent), returns the stream's flow_id
streamID, _ := conn.PushFlow(ctx, wire.Flow{
    ProtocolTag: "myproto/stream",
    Request:     &wire.FlowMessage{Method: "STREAM_OPEN"},
})

// Emit chunks (children) in order
conn.PushFlow(ctx, wire.Flow{
    ParentFlowID: streamID,
    Direction:    "server_to_client",
    Request:      &wire.FlowMessage{Body: chunk},
})

// Close (two-phase re-emit of the parent)
conn.CompleteFlow(ctx, streamID, nil, time.Now())
```

Session/tunnel envelopes follow the same pattern with `Direction: "bidirectional"` and `Method: "TUNNEL"`.

#### Non-decodable bodies

When sectool can't natively decode the wire body, supply both the logical and raw forms; unmutated replay resends `body_raw`, a mutated body re-encodes through `body_codec` (see [Flow model](#flow-model)):

```go
Request: &wire.FlowMessage{
    Body:    decodedPayload, // logical body tools operate on
    BodyRaw: wireBytes,      // verbatim wire bytes for unmutated replay
    BodyCodec: &wire.BodyCodec{
        Transforms:  []string{"decrypt-noise", "decompress-zstd"},
        ContentType: "application/octet-stream",
    },
}
```

### Rules

The SDK maintains a hot-path `RuleCache`, refreshed atomically on each `sync_rules` push. Access via `conn.Rules()`; scoped rules for other adapters are filtered out automatically (see [Rules](#rules)).

```go
mutatedBody, firedRules := conn.Rules().ApplyBody(body, wire.RuleTypeRequestBody)
mutatedHeaders, firedRules := conn.Rules().ApplyHeaders(headers, wire.RuleTypeRequestHeader) // case-insensitive
mutatedPayload, firedRules := conn.Rules().ApplyWS(payload, wire.RuleTypeWSToServer)
```

### Upstream connections

Request that sectool open a TCP connection on your behalf:

```go
upstreamID, err := conn.DialUpstream(ctx, wire.DialUpstreamParams{
    Host: "api.example.com",
    Port: 443,
    TLS:  &wire.DialUpstreamTLS{Enabled: true, SNI: "api.example.com"},
})
```

Sectool applies scope policy and records the dial. Bytes flow through the same event model: inbound via `OnStreamDeliver`, outbound via returned writes. Omit `Host`/`Port` and set `ParentFlowID` to dial that flow's original destination.

### Cross-adapter invocation

Route an outbound message through another adapter's injection target:

```go
result, err := conn.InvokeAdapter(ctx, wire.InvokeAdapterParams{
    Adapter: "http/1.1",
    Target:  json.RawMessage(`{"url":"https://api.example.com/key"}`),
    Payload: json.RawMessage(`{"method":"GET","headers":{}}`),
})
```

The reserved destination `sectool` originates through the in-process HTTP proxy's native send path.

### Invoking sectool core tools

Query or drive core sectool tools by name from within a handler or tool implementation:

```go
result, err := conn.CoreInvoke(ctx, "proxy_poll", map[string]any{"mode": "flows", "limit": 10})
```

`result.Content` is the tool's markdown output. `core_invoke` reaches the same core tools agents call — both reads and writes. Internal tools are not invocable.

### Replay and origination (OnSidecarSend)

When an agent calls `replay_send` on a flow captured by your adapter, sectool routes it to `OnSidecarSend`. The params carry the source flow inline, so you have `body`, `body_raw`, and `body_codec` without a round-trip:

```go
func (h *myHandler) OnSidecarSend(p wire.SidecarSendParams) (wire.SidecarSendResult, error) {
    msg := wire.FlowMessage{
        Method:  p.Flow.Request.Method,
        Path:    p.Flow.Request.Path,
        Headers: slices.Clone(p.Flow.Request.Headers),
        Body:    p.Flow.Request.Body,
    }
    if err := sidecar.ApplyMutations(&msg, p.Mutations); err != nil {
        return wire.SidecarSendResult{}, err
    }
    // Re-encode and send per adapter configuration; emit resulting flow(s) via
    // conn.PushFlow() with parent_flow_id set to p.FlowID
    return wire.SidecarSendResult{NewFlowIDs: []string{newFlowID}}, nil
}
```

Set the result flow's `parent_flow_id` to the source (`p.FlowID`). sectool files any flow you push from `OnSidecarSend` whose parent is the flow being replayed into replay history automatically, reported with source `replay` like a native replay.

#### Mutation operations

`sidecar.ApplyMutations(&msg, mutations)` applies an ordered list of `{op, name, value}` operations in array order:

| `op` | `name` | `value` |
|------|--------|---------|
| `set_header` / `remove_header` | header name | new value (omit for remove) |
| `set_json` / `remove_json` | dot/bracket path | JSON value (omit for remove) |
| `set_form` / `remove_form` | form field name | new value (omit for remove) |
| `set_query` / `remove_query` | query param name | new value (omit for remove) |
| `method` / `path` / `query` | (unused) | full replacement string |
| `body` | (unused) | full body replacement |

The op names are exported as constants in `sidecar/wire` (`wire.OpSetHeader`, `wire.OpSetQuery`, …). `set_query`/`remove_query` edit the raw query in place, preserving parameter order and percent-encoding.

As the flow's sole owner (see [Mutation ownership](#mutation-ownership)), the sidecar applies the ops once, then re-encodes and re-establishes any protocol binding (signatures, framing, compression). The `github.com/go-appsec/toolbox/pkg/mutate` helpers (`JSON`, `Form`, `Query`, `ReplaceCaseInsensitive`, header render/parse) back `ApplyMutations` and the `RuleCache`, and are available directly when you need to mutate outside them.

### Custom MCP tools

Register protocol-specific tools that agents discover through the normal MCP `tools/list`:

```go
MCPTools: []wire.MCPTool{
    {
        Name:        "mqtt_subscribe",
        Description: "Subscribe to an MQTT topic and capture messages as flows",
        InputSchema: json.RawMessage(`{"type":"object","properties":{"topic":{"type":"string"}}}`),
    },
}
```

Invocation reaches `OnInvokeTool` with sectool-validated arguments. The handler may read state via `CoreInvoke` and emit flows via `PushFlow`.

### Proactive stream operations

Two actions outside of event responses:

```go
conn.CloseStream(streamID, "session ended", false)  // close after the writes already sent
conn.CloseStream(streamID, "stale", true)           // abort now, dropping queued writes
conn.StreamWrite(streamID, keepaliveBytes)          // write without a triggering event
```

`StreamWrite` calls are applied in send order, so they also suit a synchronous state machine that produces output with no triggering event, and they stay ordered against writes returned from stream events.

### Logging and metrics

```go
conn.Log("info", "connected to broker", map[string]any{"broker": "mqtt.example.com"})
conn.ReportMetrics(map[string]int64{"frames_parsed": 150}, map[string]float64{"buffer_bytes": 4096})
```

### Error handling

The SDK surfaces JSON-RPC 2.0 errors as `*wire.Error` (`{Code, Message, Data}`). Sectool-specific codes occupy `-33000..-33999`; `Dial` maps `-33001` to `ErrVersionUnsupported`. See [Error object](#error-object) for the full code table.

---

## JSON-RPC 2.0 wire protocol

For implementing a sidecar without the Go SDK. Every field name below is a JSON tag from the shared `sidecar/wire` package, which both peers import, so the two ends encode byte-identical structures. Read [Concepts](#concepts) first for the semantics.

### Framing

A single connection carries a sequence of length-prefixed messages:

- **4 bytes** — big-endian `uint32` payload length (counts the JSON bytes only).
- **N bytes** — the JSON-RPC 2.0 message.

No delimiter, no trailing newline. Frames are bounded to **128 MiB** on both read and write; a frame exceeding it errors with `-33201` (a write is refused, an oversized read prefix is rejected before allocating). `max_body_bytes` governs only what history retains, never what is forwarded.

### Message envelope

```json
{ "jsonrpc": "2.0", "id": 1, "method": "push_flow", "params": { ... } }
```

| Field | Type | Notes |
|-------|------|-------|
| `jsonrpc` | string | always `"2.0"` |
| `id` | number | unsigned integer, present on requests and responses |
| `method` | string | present on requests and notifications |
| `params` | object | method parameters |
| `result` | object | success response payload |
| `error` | object | error response (see below) |

Message kind is discriminated by presence:

- **Request** — has `id` and `method` (expects a response).
- **Response** — has `id`, no `method` (carries `result` or `error`).
- **Notification** — has `method`, no `id` (fire-and-forget).

Both peers are symmetric: either may issue requests and notifications. `id` is an incrementing unsigned integer, unique per outstanding request per direction, echoed verbatim in the response (a quoted-numeric echo, e.g. `"1"`, is also accepted). **The reader must dispatch each inbound request to a separate task**, so a handler awaiting a nested request never blocks the read loop and deadlocks the connection. Malformed frames are silently skipped, not answered.

Binary fields (`body`, `body_raw`, stream/probe `data`, `magic_bytes_prefix`) use standard-alphabet padded base64. Fields typed as raw JSON (schemas, `annotations`, structured tool output, and the adapter-validated `target`/`payload`/`params`) are embedded verbatim, not re-encoded; each method's params note which applies.

### Error object

```json
{ "code": -33001, "message": "contract major mismatch: `sectool` 1, sidecar 2",
  "data": { "adapter": "my-protocol" } }
```

`data` (all optional): `adapter`, `conflict_adapter`, `flow_id`, `stream_id`.

Standard JSON-RPC codes `-32601` (method not found) and `-32603` (internal) apply. Sectool-specific codes occupy the reserved range `-33000..-33999`:

| Code | Meaning |
|------|---------|
| `-33000` | Registration rejected |
| `-33001` | Version unsupported (wrong major or newer minor) |
| `-33002` | Duplicate registration |
| `-33003` | Capability conflict |
| `-33004` | Tool name conflict |
| `-33005` | Not registered |
| `-33100` | Flow emission rejected |
| `-33101` | `core_invoke` validation rejected |
| `-33102` | Rule shape rejected |
| `-33200` | Framing violation |
| `-33201` | Oversized message |
| `-33202` | Unknown `stream_id` |
| `-33203` | `claim_probe` fault (probe errored) |
| `-33299` | Transport internal |
| `-33300` | `dial_upstream` scope rejection |
| `-33301` | `dial_upstream` dial failed |
| `-33302` | `dial_upstream` TLS failed |
| `-33400` | Unknown destination adapter |
| `-33401` | Destination missing `injection_target` |
| `-33402` | Native origination / send failed |

A `claim_probe` returning `{"claim": false}` is normal control flow, not an error.

### Method catalog

| Method | Direction | Kind |
|--------|-----------|------|
| `register` | sidecar → sectool | request |
| `push_flow` | sidecar → sectool | request |
| `core_invoke` | sidecar → sectool | request |
| `dial_upstream` | sidecar → sectool | request |
| `invoke_adapter` | sidecar → sectool | request |
| `log` | sidecar → sectool | notification |
| `report_metrics` | sidecar → sectool | notification |
| `close_stream` | sidecar → sectool | notification |
| `stream_write` | sidecar → sectool | notification |
| `sync_rules` | sectool → sidecar | request |
| `sidecar_send` | sectool → sidecar | request |
| `invoke_tool` | sectool → sidecar | request |
| `stream_open` | sectool → sidecar | request |
| `stream_deliver` | sectool → sidecar | request |
| `claim_probe` | sectool → sidecar | request |
| `shutdown` | sectool → sidecar | request |
| `stream_ended` | sectool → sidecar | notification |
| `ping` / `pong` | either direction | notification (or request) |

Messages are ordered per concern, not globally. All of a stream's bytes travel as `stream_write` on one ordered path, so they reach its socket in the order the sidecar sent them, and `close_stream` takes its place in that same order. `log` and `report_metrics` keep their order against each other. `sync_rules` pushes apply in the order sectool sent them. Everything else, including `ping`/`pong` and the remaining request/response traffic, is handled concurrently.

Sectool queues each stream's pending writes. A stream event's writes are paced by the queue, so a slow client throttles the stream feeding it. A proactive `stream_write` cannot be paced without stalling other streams, so outrunning a stalled client by more than the queue depth closes that stream, reported as the usual `stream_ended`.

### Methods

Params and results below list JSON field names. Reused shapes (`Flow`, `FlowMessage`, `Rule`, `Capabilities`, …) are defined under [Shared structs](#shared-structs).

#### register (sidecar → sectool)

Issued exactly once, first message on the connection.

**params:** `name` (string, required), `protocol_version` (`{major, minor}`, required), `protocols` (`[string]`, optional), `capabilities` (object, optional), `mcp_tools` (`[MCPTool]`, optional), `instance_id` (string UUID, optional), `resume` (bool, optional).

**result:** `protocol_version` (the effective `{major, minor}`), `server_time` (RFC3339Nano string).

Rejected with `-33001` when the major differs (any direction) or the sidecar's minor is newer than sectool's. Otherwise the session runs at the sidecar's (≤ sectool) minor, echoed in the result's `protocol_version`.

#### push_flow (sidecar → sectool)

**params:** a bare `Flow` object (not wrapped). Empty `flow_id` is first emission; set `flow_id` to target an existing flow for two-phase completion or teardown. See [Flow model](#flow-model).

**result:** `{ "flow_id": string }`.

#### core_invoke (sidecar → sectool)

Invokes a core sectool MCP tool by name, reusing the same handlers agents call.
Internal tools are not invocable.

**params:** `tool` (string, a core MCP tool name, e.g. `proxy_poll`, `proxy_respond_add`), `params` (raw JSON, that tool's parameters).

**result:** `content` (string, the tool's markdown), `is_error` (bool, optional).

#### dial_upstream (sidecar → sectool)

**params:** `host` (string, optional), `port` (int, optional), `tls` (`{enabled, sni?, alpn?, skip_verify?}`, optional), `parent_flow_id` (string, optional, supplies the default destination and links the dial). Omitting `host`/`port` dials `parent_flow_id`'s original destination.

**result:** `{ "stream_id": string }`, or a `-3330x` error on scope/dial/TLS failure. Bytes then flow via `stream_deliver` events and `stream_write`.

#### invoke_adapter (sidecar → sectool)

**params:** `adapter` (string, required, destination with an `injection_target`), `target` (raw JSON, validated by the destination adapter), `payload` (raw JSON, likewise), `mutations` (`[Mutation]`, optional), `wait_for_response` (bool, optional, default true).

**result:** `new_flow_ids` (`[string]`), `response` (`FlowMessage`, when waited). Destination `sectool` originates via the native HTTP send path; `target`/`payload` then mirror `request_send` (`{url, method, headers, body, follow_redirects, force}`).

#### log (sidecar → sectool, notification)

**params:** `level` (string, optional), `message` (string), `fields` (object, optional).

#### report_metrics (sidecar → sectool, notification)

**params:** `counters` (`{name: int64}`), `gauges` (`{name: number}`).

#### close_stream (sidecar → sectool, notification)

**params:** `stream_id` (string), `reason` (string, optional), `abort` (bool, optional). Proactively closes a client-facing or dialed upstream stream after the writes already queued for it. Set `abort` to close immediately and drop them.

#### stream_write (sidecar → sectool, notification)

**params:** `stream_id` (string), `data` (standard-alphabet padded base64). Proactive write for keepalives and for output produced with no triggering event. As a notification it is fire-and-forget: an unknown `stream_id` is logged and dropped by sectool (`-33202`) and is not reported back to the sidecar.

#### sync_rules (sectool → sidecar)

**params:** `rules` (`[Rule]`, the full ordered list to apply). The sidecar replaces its cache wholesale; an empty list clears it.

**result:** `ack` (bool). On an unsupported rule shape, return `-33102` naming the `rule_id`; the sidecar keeps its previous rules.

Pushed once at registration (before the `register` result, even when the list is empty, so a reconnecting sidecar never keeps a stale cache) and again on every change. Sectool serializes pushes to a sidecar and waits for each ack before the next, so a later snapshot never overwrites a newer one; each push is bounded by a timeout and fails open (the sidecar keeps capturing its traffic) so a stalled sidecar can't wedge later pushes. A stalled frame write will eventually close the connection.

#### sidecar_send (sectool → sidecar)

The method behind agent `replay_send` and the destination side of `invoke_adapter`. Never called by agents directly.

**params:** `flow_id` (string, optional, set to replay), `flow` (`Flow`, the resolved source passed inline on replay), `destination` (string, optional `scheme://host[:port]` routing override), `target` / `payload` (raw JSON, for origination), `mutations` (`[Mutation]`), `follow_redirects` (bool, optional), `force` (bool, optional), `wait_for_response` (bool, optional, default true), `stream_strategy` (string, optional — `per_chunk` (default) replays a stream's children in order, `collapsed` merges them; adapters whose protocol forbids reordering reject `collapsed`).

**result:** `new_flow_ids` (`[string]`), `writes` (`[StreamWrite]`, optional first outbound bytes), `response` (`FlowMessage`, when waited).

#### invoke_tool (sectool → sidecar)

**params:** `name` (string, a registered tool), `arguments` (raw JSON, sectool-validated against `input_schema`).

**result:** `content` (string, optional markdown), `structured_content` (raw JSON, optional), `is_error` (bool, optional).

#### stream_open (sectool → sidecar)

**params:** `stream_id` (string), `host`, `path`, `peer_addr` (strings, optional), plus `request_flow_id` (string) and `request_headers` (`[Header]`), present only for an `upgrade_claim`, absent for `early_claim`.

**result:** `{ "wrote_to": [string] }` (usually empty; the client speaks first).

#### stream_deliver (sectool → sidecar)

**params:** `stream_id` (string), `data` (standard-alphabet padded base64, a raw transport chunk **not** frame-aligned; see [Stream events](#stream-events) for reassembly).

**result:** `{ "wrote_to": [string] }`, the stream ids the sidecar wrote to while handling the event. The bytes themselves travel as `stream_write` notifications sent before the response, keeping them ordered against proactive writes; `wrote_to` lets sectool pace those streams. Sectool awaits this response before the next chunk (per-stream ordering). The sidecar may nest `dial_upstream`, `core_invoke`, or `push_flow`.

#### claim_probe (sectool → sidecar)

**params:** `host`, `port`, `peer_addr`, `sni` (optional), `data` (standard-alphabet padded base64, buffered opening bytes).

**result:** `{ "claim": bool }`. True takes the connection; false declines to next probe or HTTP fallthrough. See [Capabilities](#capabilities).

#### shutdown (sectool → sidecar)

**params:** `drain_seconds` (int). **result:** `{ "ack": true }`. The sidecar finishes in-flight work, emits a final `report_metrics`, and closes.

#### stream_ended (sectool → sidecar, notification)

**params:** `stream_id` (string), `reason` (string, optional). The sidecar reacts by closing any paired stream.

#### ping / pong (either direction)

A `ping` request (has `id`) is answered with an empty `{}` result. A `ping` notification (no `id`) is answered with a `pong` notification. Sectool records a received `pong` as liveness, and marks a sidecar unhealthy after enough consecutive intervals without a reply.

### Shared structs

#### Flow

```json
{
  "flow_id": "", "adapter": "", "protocol_tag": "mqtt/3.1.1",
  "direction": "client_to_server", "parent_flow_id": "",
  "scheme": "", "port": 0,
  "request":  { /* FlowMessage */ },
  "response": { /* FlowMessage */ },
  "started_at": "2026-07-02T09:30:00Z", "completed_at": "0001-01-01T00:00:00Z",
  "annotations": {}
}
```

All fields `omitempty`. `annotations` is a free-form object the sidecar owns; sectool stores it verbatim. Replay classification is not annotation-driven: sectool files a pushed flow into replay history when its `parent_flow_id` is the source of an in-flight replay (see [Replay and origination](#replay-and-origination-onsidecarsend)).

Timestamps are RFC 3339 strings. An empty `flow_id` is first emission (sectool assigns); set `flow_id` to re-target an existing flow for two-phase completion or teardown.

#### FlowMessage

```json
{
  "method": "PUBLISH", "path": "/sensors/temp", "query": "",
  "status_code": 0, "status_text": "",
  "headers": [ { "name": "QoS", "value": "1" } ],
  "body": "<base64>", "body_raw": "<base64>",
  "body_codec": { "transforms": ["decrypt-noise"], "content_type": "application/octet-stream" }
}
```

`body` is the logical payload every tool operates on; encoded as standard-alphabet padded base64 on the wire. `body_raw` (also base64) and `body_codec` carry the verbatim wire form when `body` is not natively decodable — see [Flow model](#flow-model). `status_code` / `status_text` are the response side's outcome.

#### Header

`{ "name": string, "value": string }`, an ordered array, not a map; duplicates and order are preserved.

#### StreamWrite

`{ "stream_id": string, "data": "<base64>" }`, bytes for sectool to write. `stream_id` may differ from the stream the event arrived on; that is how client bytes are forwarded upstream.

#### Rule

```json
{ "rule_id": "r1", "type": "request_body", "label": "", "is_regex": false,
  "find": "foo", "replace": "bar", "adapter": "" }
```

`type` ∈ `request_header`, `request_body`, `response_header`, `response_body`, `ws:to-server`, `ws:to-client`, `ws:both`. An empty `adapter` applies to every adapter; otherwise it names the owning sidecar.

#### Capabilities

```json
{
  "early_claims": [{
    "port_range": { "low": 9443, "high": 9443 },
    "tls": {
      "terminate": true, "sni_match": "mqtt.example.com",
      "cert": {
        "dns_names": ["alt.example.com"], "ip_addresses": ["10.0.0.1"],
        "uris": ["spiffe://example.com/svc"], "emails": [], "common_name": ""
      }
    },
    "magic_bytes_prefix": "<base64>", "host_match": "",
    "probe": false, "probe_max_bytes": 0
  }],
  "upgrade_claims": [{
    "host_pattern": "example\\.com", "path_pattern": "/ws/custom",
    "upgrade_signal": "http_101", "method_set": ["GET"]
  }],
  "injection_targets": [{ "target_schema": { /* JSON Schema */ } }]
}
```

`upgrade_signal` ∈ `http_101`, `connect`; empty means `http_101`. Each seam is a list; omit or leave empty the ones you don't claim, and declare more than one entry to claim multiple entry points. `magic_bytes_prefix` is standard-alphabet padded base64, and `port_range` `{ "low": 0, "high": 0 }` matches any port. `host_pattern` and `path_pattern` are whole-value RE2 patterns; see [Early claim matching](#early-claim-matching) and [Upgrade claim matching](#upgrade-claim-matching) for how each matcher applies per seam.

#### Mutation

`{ "op": string, "name": string, "value": string }`, applied in array order. See the [op table](#mutation-operations).

#### MCPTool

`{ "name": string, "description": string, "input_schema": <JSON Schema>, "annotations": <JSON> }`.
