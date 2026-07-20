## Project Overview

**go-appsec/toolbox (sectool)** is a CLI and MCP toolkit for human and LLM agent collaboration for application security testing.

Key characteristics:
- MCP-primary architecture: single API serves both agents and CLI
- CLI is a thin client over MCP for human interaction
- Global config at `~/.sectool/config.json` (auto-created)
- All output in markdown format for LLM consumption
- Pluggable backend architecture (native built-in proxy or Burp MCP for HTTP, Interactsh for OAST, Colly for crawling)

## Build Commands

```bash
make build          # Build to bin/sectool
make build-cross    # Cross-compile (linux/darwin, amd64/arm64)
make test           # Quick tests (-short flag)
make test-all       # Full tests with -race and coverage
make lint           # Run golangci-lint and go vet
```

## Architecture

```
CLI Command → MCP Client → MCP Server → Backends (Built-in Proxy or Burp MCP, OAST, Crawler)
MCP Agent  → MCP Server → Backends (Built-in Proxy or Burp MCP, OAST, Crawler)
```

### Core Files

- `sectool/main.go` - Entry point; routes `mcp` subcommand to server mode, else CLI command dispatch
- `sectool/config/config.go` - Config loading/saving, defaults, auto-creation
- `sectool/config/socket_unix.go` / `socket_windows.go` - `DefaultSidecarSocket`: per-OS sidecar IPC address (Unix domain socket, or loopback TCP on Windows)
- `sectool/mcpclient/client.go` - MCP client wrapper for CLI usage
- `sectool/mcpclient/tools.go` - Typed methods for each MCP tool
- `sectool/mcpclient/types.go` - Client-specific option types (*Opts structs)
- `sectool/bundle/bundle.go` - Client-side bundle file operations for export

### Protocol

- `sectool/protocol/workflow.go` - Workflow mode constants shared between service and mcpclient
- `sectool/protocol/types.go` - Shared MCP response types (used by both service and mcpclient)

### Service Layer

- `sectool/service/server.go` - MCP server lifecycle and backend coordination
- `sectool/service/mcp_server.go` - MCP server setup, tool registration, workflow handling
- `sectool/service/mcp_proxy.go` - Proxy and flow_get tool handlers (poll, flow_get, cookie_jar, rules)
- `sectool/service/mcp_proxy_internal.go` - Internal MCP proxy tool (`_internal_history_delete`)
- `sectool/service/mcp_replay.go` - Replay tool handlers (send, request_send)
- `sectool/service/mcp_crawl.go` - Crawl tool handlers (create, seed, status, poll, sessions, stop)
- `sectool/service/mcp_oast.go` - OAST tool handlers (create, poll, get, list, delete)
- `sectool/service/mcp_encode.go` - Encode/decode tool handlers (url, base64, html)
- `sectool/service/mcp_uuid.go` - UUID generation tool handler (v4, v7)
- `sectool/service/mcp_hash.go` - Hash tool handler (md5, sha1, sha256, sha512, HMAC)
- `sectool/service/mcp_jwt.go` - JWT decode tool handler
- `sectool/service/mcp_diff.go` - Diff tool handler (structured flow comparison)
- `sectool/service/mcp_reflection.go` - Reflection tool handler (parameter reflection detection)
- `sectool/service/mcp_jssurface.go` - JS analyze tool handler (extract API surface from JS/HTML responses)
- `sectool/service/mcp_jsendpoint.go` - JS endpoint detail tool handler (per-call-site request shape by deterministic id)
- `sectool/service/js/` - JS bundle parser and extractors (tdewolff/parse/v2/js)
- `sectool/service/js/analyze.go` - main JS bundle analyzer
- `sectool/service/js/dedupe.go` - deduplication logic
- `sectool/service/js/detail.go` - per-call-site request-shape extraction (body/headers/query/path params) and deterministic EndpointID
- `sectool/service/js/extract.go` - extraction logic
- `sectool/service/js/html.go` - HTML-specific handling
- `sectool/service/js/parse.go` - parsing logic
- `sectool/service/js/scope.go` - scoping logic
- `sectool/service/js/secrets.go` - secrets detection
- `sectool/service/mcp_notes.go` - Notes tool handlers (save, list) and flow listing attachment
- `sectool/service/mcp_respond.go` - Proxy responder tool handlers (respond_add, respond_delete, respond_list); native backend only
- `sectool/service/flags.go` - MCP server flag parsing (`--port`, `--proxy-port`, `--burp`, `--workflow`, `--config`, `--notes`, `--sidecar-socket`)
- `sectool/service/backend.go` - HttpBackend, ResponderBackend, OastBackend, CrawlerBackend interfaces
- `sectool/service/backend_http_native.go` - Native built-in proxy implementation of HttpBackend
- `sectool/service/backend_http_native_respond.go` - Native backend implementation of ResponderBackend
- `sectool/service/backend_http_burp.go` - Burp MCP implementation of HttpBackend; hosts `burpFlowIndex` (flow_id ↔ Burp offset mapping)
- `sectool/service/backend_oast_interactsh.go` - Interactsh implementation of OastBackend
- `sectool/service/smtputil.go` - SMTP email header parsing utilities
- `sectool/service/backend_crawler_colly.go` - Colly-based crawler implementation
- `sectool/service/capture_filter.go` - BuildCaptureFilter: compiles proxy exclusion patterns from config
- `sectool/service/mcp_coreinvoke.go` - `CoreInvoke` dispatch for sidecars: invoke a core MCP tool by name (reuses the handlers agents call; internal tools excluded)
- `sectool/service/mcp_replay_originate.go` - Native HTTP origination for sidecar sends (`originateNative`); mirrors request_send, produces an attributable flow
- `sectool/service/mcp_sidecar_tools.go` - Recomposes the advertised MCP tool list as sidecars connect/disconnect; adds sidecar-conditional params to core tools
- `sectool/service/sidecar_replay_sink.go` - `replayRoutingSink`: diverts sidecar-performed replays (annotated `replay=true`) into the replay history store, else proxy history
- `sectool/service/search.go` - RE2 pattern compilation with LLM-friendly double-escape correction; flow content matching
- `sectool/service/httputil.go` - HTTP request/response parsing utilities
- `sectool/service/jsonutil.go` - JSON read/analysis helpers (flatten, parse list)
- `sectool/service/types.go` - Service-specific request and internal types
- `sectool/service/dedupe/dedupe.go` - Order-preserving slice deduplication helpers
- `sectool/service/fileutil/fileutil.go` - Filesystem helpers (`AtomicWriteFile`)

### Proxy Package

- `sectool/service/proxy/types/types.go` - Core proxy data model: wire-fidelity HTTP/1.1 request/response types, protocol tags, `RuleApplier` contract
- `sectool/service/proxy/types/flow.go` - `Flow` store record (generalized `HistoryEntry`): request/response `Message` under one flow_id, `ParentFlowID` for child flows
- `sectool/service/proxy/types/serialize.go` - Header/status-line serialization helpers
- `sectool/service/proxy/parser.go` - HTTP/1.1 tolerant parser with wire fidelity
- `sectool/service/proxy/validate.go` - Optional request validation
- `sectool/service/proxy/server.go` - TCP listener, accept loop, protocol detection
- `sectool/service/proxy/handler_http1.go` - Plain HTTP and HTTP-over-TLS handler
- `sectool/service/proxy/handler_connect.go` - CONNECT tunnel and TLS MITM with ALPN negotiation
- `sectool/service/proxy/handler_http2.go` - HTTP/2 stream handler with HPACK
- `sectool/service/proxy/handler_websocket.go` - WebSocket frame proxying
- `sectool/service/proxy/adapter_shims.go` - Wraps the built-in HTTP/1.1, HTTP/2, and WebSocket handlers as protocol adapters registered with the registry
- `sectool/service/proxy/cert.go` - CA and per-hostname certificate management
- `sectool/service/proxy/history.go` - Thread-safe history storage
- `sectool/service/proxy/filter.go` - CaptureFilter type, SetCaptureFilter/ShouldCapture
- `sectool/service/proxy/interceptor.go` - ResponseInterceptor interface for serving canned responses in place of upstream requests
- `sectool/service/proxy/compression.go` - gzip/deflate utilities
- `sectool/service/proxy/sender.go` - Wire-fidelity request sender (H1 and H2)
- `sectool/service/proxy/httputil.go` - HTTP method extraction, header grouping, and raw query modification utilities
- `sectool/service/proxy/hpack.go` - HPACK encoder/decoder management

### Protocol Adapters

Generalized capture pipeline letting built-in and out-of-process protocol adapters share the native proxy's connection seams. See `sidecar/README.md` for the full contract.

- `sectool/service/proxy/protocol/adapter.go` - Adapter interfaces and claim contexts (`EarlyClaimCtx`, `UpgradeClaimCtx`, `UpgradeConns`)
- `sectool/service/proxy/protocol/registry.go` - Ordered claim-seam registry (first claim wins; fallthrough HTTP adapter last); runtime insert/remove for sidecar bridges
- `sectool/service/proxy/protocol/sidecar/manager.go` - Sidecar registry and connection lifecycle (`Manager`, `HandleConn`); per-connection `session`
- `sectool/service/proxy/protocol/sidecar/listener.go` - Sidecar IPC listener and accept loop
- `sectool/service/proxy/protocol/sidecar/listener_unix.go` / `listener_windows.go` - Per-OS listen (Unix domain socket, or loopback TCP on Windows)
- `sectool/service/proxy/protocol/sidecar/register.go` - `register` handshake: validation, version negotiation (major reject, minor cap), resume/reconnect, rules snapshot
- `sectool/service/proxy/protocol/sidecar/conflict.go` - Registration conflict checks (port ranges, claim matchers, tool names)
- `sectool/service/proxy/protocol/sidecar/record.go` - `Record` registry entry per adapter; `Liveness` heartbeat tracking
- `sectool/service/proxy/protocol/sidecar/bridge.go` - Adapter shim exposing a sidecar's claims to the registry and driving claimed streams
- `sectool/service/proxy/protocol/sidecar/streams.go` - Per-connection stream set; client/upgrade/upstream byte pumping and `writes` application
- `sectool/service/proxy/protocol/sidecar/dial.go` - `dial_upstream` handler: scope policy, TLS termination, audit dial flow
- `sectool/service/proxy/protocol/sidecar/flow.go` - `push_flow`/`core_invoke`/`log` handlers and `FlowSink`/`CoreService`/`RuleSource` interfaces
- `sectool/service/proxy/protocol/sidecar/rules.go` - `PushRules`: pushes the adapter-filtered rule snapshot via `sync_rules`
- `sectool/service/proxy/protocol/sidecar/send.go` - Replay/origination routing: `Manager.SidecarSend` (to the owning adapter, source flow inline) and `invoke_adapter` (records `annotations.invoked_by`)
- `sectool/service/proxy/protocol/sidecar/tools.go` - Sidecar-registered MCP tool listing (`AdapterTools`) and delegated invocation (`InvokeTool`)

### Sidecar SDK (`sidecar/`)

Go client library for building out-of-process protocol adapters; see `sidecar/README.md`. Must stay in sync with the wire types.

- `sidecar/conn.go` - `Conn`, `Dial` (register handshake, `ErrVersionUnsupported`), `Serve`, inbound request/notification routing
- `sidecar/dial.go` - `Conn.DialUpstream`
- `sidecar/handler.go` - `Registration`, `Handler` callback interface, `BaseHandler` no-op defaults
- `sidecar/flow.go` - Flow emission (`PushFlow`, `CompleteFlow`, `EmitMutatedPair`), `Log`, `ReportMetrics`, `CoreInvoke`
- `sidecar/send.go` - Send surface: `ApplyMutations` (ordered §3.4 ops via `pkg/mutate`) and `Conn.InvokeAdapter`
- `sidecar/stream.go` - `CloseStream`, `StreamWrite`, and the `Forward` writes helper
- `sidecar/rules.go` - `RuleCache`: hot-path find/replace scoped to this adapter
- `sidecar/reassembly.go` - `Reassembler`: buffers stream bytes into complete protocol frames
- `sidecar/net_unix.go` / `sidecar/net_windows.go` - Per-OS dial network selection (UDS vs loopback TCP)

### Sidecar Wire Protocol (`sidecar/wire/`)

Shared JSON-RPC 2.0 contract types imported by both the SDK and the service side (byte-identical encoding).

- `sidecar/wire/methods.go` - Contract version constants and JSON-RPC method-name constants
- `sidecar/wire/params.go` - All params/result structs (register, flow, rule, capabilities, mutation, stream, dial, invoke, …)
- `sidecar/wire/jsonrpc.go` - `Message` envelope and request/response/notification discriminators
- `sidecar/wire/peer.go` - `Peer`: framed JSON-RPC transport, symmetric call/notify, request dispatch
- `sidecar/wire/codec.go` - Length-prefixed frame read/write (`MaxFrameBytes`)
- `sidecar/wire/errors.go` - `Error`/`ErrorData` and the sectool-specific error code registry (-33000..-33999)

### Shared Mutation Helpers (`pkg/mutate/`)

- `pkg/mutate/json.go` - JSON body set/remove by dot/bracket path (no HTML escaping)
- `pkg/mutate/form.go` - Form (`application/x-www-form-urlencoded`) body set/remove; consumed by service replay and the sidecar SDK

### Burp MCP Client

- `sectool/service/mcp/burp.go` - SSE-based Burp Suite MCP client
- `sectool/service/mcp/types.go` - MCP-specific types

### State Management

- `sectool/service/store/storage.go` - Storage interface and in-memory implementation
- `sectool/service/store/spill.go` - SpillStore: disk-paging Storage with LRU eviction, encryption, and compaction
- `sectool/service/store/serialize.go` - Msgpack serialization helpers
- `sectool/service/store/replay_history.go` - Replay request/response storage with meta/payload split
- `sectool/service/store/notes.go` - Note storage with reverse flow index
- `sectool/service/ids/ids.go` - Base62 random IDs using crypto/rand

### CLI Commands

- `sectool/proxy/flags.go` - Subcommand parsing (summary/list/get/cookies/export/rule/clear)
- `sectool/proxy/clear.go` - Clear command implementation (remove flows from history)
- `sectool/proxy/list.go` - List/summary/get command implementation
- `sectool/proxy/cookies.go` - Cookies command implementation
- `sectool/proxy/export.go` - Export command implementation
- `sectool/proxy/rule.go` - Rule CRUD command implementations
- `sectool/crawl/flags.go` - Crawl subcommand parsing
- `sectool/crawl/crawl.go` - Crawl command implementations
- `sectool/replay/flags.go` - Subcommand parsing (send/get/create)
- `sectool/replay/replay.go` - Command implementations
- `sectool/oast/flags.go` - Subcommand parsing (create/poll/list/delete)
- `sectool/oast/oast.go` - Command implementations
- `sectool/encoding/flags.go` - Encode/decode subcommand parsing (url/base64/html)
- `sectool/encoding/encoding.go` - Encoding/decoding implementations
- `sectool/hash/flags.go` - Hash subcommand parsing
- `sectool/hash/hash.go` - Hash computation (plain and HMAC)
- `sectool/jwt/flags.go` - JWT subcommand parsing
- `sectool/jwt/jwt.go` - JWT decode and inspection
- `sectool/diff/flags.go` - Diff subcommand parsing
- `sectool/diff/diff.go` - Diff command implementation (CLI formatting and display)
- `sectool/reflected/flags.go` - Reflected subcommand parsing
- `sectool/reflected/reflected.go` - Reflected command implementation
- `sectool/js/flags.go` - JS analyze subcommand parsing
- `sectool/js/js.go` - JS analyze command implementation

### Shared CLI Utilities

- `sectool/cliutil/output.go` - Output writer and color mode detection (NO_COLOR/FORCE_COLOR aware)
- `sectool/cliutil/colors.go` - Status-code coloring helpers
- `sectool/cliutil/styles.go` - go-pretty table styles (light/simple)
- `sectool/cliutil/table.go` - NewTable helper and row painters
- `sectool/cliutil/hints.go` - Muted hint and summary print helpers
- `sectool/cliutil/suggest.go` - "Did you mean" levenshtein suggestions for unknown commands
- `sectool/util/strutil.go` - TruncateString and other shared string utilities

### Config

Global config at `~/.sectool/config.json` (auto-created with defaults):

```json
{
  "version": "<auto-set schema version>",
  "mcp_port": 9119,
  "proxy_port": 8080,
  "burp_required": false,
  "max_body_bytes": 10485760,
  "include_subdomains": true,
  "allowed_domains": [],
  "exclude_domains": [],
  "interactsh_server_url": "",
  "interactsh_auth_token": "",
  "proxy": {
    "dial_timeout_secs": 20,
    "read_timeout_secs": 240,
    "write_timeout_secs": 60,
    "exclude_extensions": "<RE2 alternation, see DefaultExcludeExtensions>",
    "full_buffer": false
  },
  "crawler": {
    "disallowed_paths": ["*logout*", "*signout*", "*sign-out*", "*delete*", "*remove*"],
    "delay_ms": 200,
    "parallelism": 2,
    "max_depth": 20,
    "max_requests": 2000,
    "extract_forms": true,
    "submit_forms": false,
    "respect_robots": false,
    "recon": false
  }
}
```

Domain scoping rules:
- `exclude_domains`: always takes precedence, always matches subdomains
- `allowed_domains`: strict allowlist when non-empty; respects `include_subdomains` for subdomain matching
- Neither configured: no restriction (default)

Proxy capture exclusion filters (RE2 patterns, `proxy` section):
- `exclude_extensions` (`*string`): matches file extension from path (no dot), anchored. nil → default (see `DefaultExcludeExtensions`), `""` → disabled
- Matching requests are still proxied but never stored in history

Streaming responses (`proxy` section):
- Response bodies stream to the client per unit (chunk/read/DATA frame) and the flow is stored at response-head time (visible with zero `completed_at`), growing as data arrives — SSE, long-poll, and chunked downloads. `flow_get` reports `in_progress: true` while streaming; poll again for more.
- `full_buffer` (`bool`, default `false`): when a response has body match/replace rules, buffer the whole body before applying them instead of streaming per-chunk. Streaming applies body rules per chunk (a match spanning a chunk boundary is missed); enable `full_buffer` for whole-body rule correctness. Compressed or Content-Length-framed responses with body rules always buffer regardless of this flag.
- Scope: response bodies over H1, H2, and the proxy path. Native `replay_send`/`request_send` responses are still read fully before storing.

Interim (1xx) responses, HTTP/1.1:
- The proxy answers `Expect: 100-continue` itself, before reading the request body (H1 buffers the whole request, so waiting on the origin would deadlock the client). The `Expect` header still reaches the origin unchanged and a `417` is relayed normally, but the client's upload is no longer gated by it; use `request_send`/`replay_send` to probe origin `Expect` handling directly.
- An origin `100` duplicating the locally-sent one is recorded but not relayed, so the client sees exactly one.
- `flow_get` reports `interim_responses` as objects: `source` (`proxy` = synthesized by sectool, `origin` = from upstream), `wire`, and `relayed` (whether the client received it).

### Export Bundle Layout

Bundles at `./sectool-requests/<flow_id>/`: `request.http` (headers + body placeholder), `body` (raw binary-safe), `request.meta.json` (method/URL/timestamps), `response.http`, `response.body`

## Key Types

**Backend Interfaces (`sectool/service/backend.go`):**
- `HttpBackend` - proxy history (get/regex), request sending, match/replace rules CRUD
- `ResponderBackend` - custom canned-response registration by origin/path; native proxy only
- `OastBackend` - OAST session create/delete, event polling, session listing
- `CrawlerBackend` - crawl session lifecycle and result retrieval

**Store (`sectool/service/store/`):**
- `Storage` - key-value blob interface (`memStorage`, `SpillStore` disk-paging)
- `ReplayHistoryStore` - replay storage with meta/payload split
- `NoteStore` - note storage with reverse flow_id index

## MCP Tools

**MCP server:** `sectool mcp [--proxy-port PORT] [--burp] [--port PORT] [--workflow MODE]` (default port 9119, auto-detects backend)

- `workflow` - select mode (explore/test-report) for task-specific instructions
- `proxy_poll` - query proxy history: summary or list with filters
- `flow_get` - full request/response for any flow (proxy, replay, or crawl)
- `cookie_jar` - extract and deduplicate cookies; overview without filters, full values and JWT decode with name/domain filter
- `proxy_rule_list` - list match/replace rules
- `proxy_rule_add` - add match/replace rule
- `proxy_rule_delete` - delete rule
- `proxy_respond_add` - register a canned response for a given origin/path; native proxy only
- `proxy_respond_delete` - delete a responder by ID or label
- `proxy_respond_list` - list registered responders
- `crawl_create` - start crawl from URLs or proxy flow seeds
- `crawl_seed` - add seeds to running crawl
- `crawl_status` - crawl progress metrics
- `crawl_poll` - query results: summary, flows, forms, or errors
- `crawl_sessions` - list all crawl sessions
- `crawl_stop` - stop a running crawl session
- `replay_send` - send with modifications; returns flow_id for use with flow_get
- `request_send` - send new HTTP request from scratch; returns flow_id for use with flow_get
- `oast_create` - create OAST session for out-of-band testing; optional `redirect_target` for 307 redirect responses (server-dependent)
- `oast_poll` - poll events: summary or list
- `oast_get` - structured event details; optional `fields` filter (dest, headers, body)
- `oast_list` - list active OAST sessions
- `oast_delete` - delete OAST session
- `encode` - encode a string (url, base64, html)
- `decode` - decode a string (url, base64, html)
- `uuid_generate` - generate UUIDs (v4 default, v7 time-ordered)
- `hash` - compute hash digest (md5, sha1, sha256, sha512, HMAC)
- `jwt_decode` - decode and inspect JWT tokens
- `diff_flow` - compare two captured flows with structured, content-type-aware diffing
- `find_reflected` - detect request parameter values reflected in the response
- `js_surface` - extract API surface from a JavaScript or HTML flow (endpoints, routes, sockets, URL literals, external scripts); endpoints with extractable request shape carry an `endpoint_id`
- `js_endpoint` - expand one `js_surface` endpoint into its full per-call-site request shape (body fields, headers, query, path params); addressed as `<flow_id>.<endpoint_id>`
- `notes_save` - create, update, or delete notes/findings linked to flows (requires `--notes`)
- `notes_list` - list saved notes with filters (requires `--notes`)

## CLI Commands

CLI subcommands (`sectool <module> <sub>`) generally provide access to the MCP tools above, with presentation tweaks for human use (tables, color, `--limit`, local export bundles). A running MCP server is required; the few extras beyond the MCP surface are `proxy export`, `crawl export`, and `version`.

## Development Guidelines

### CLI and MCP Parity

- CLI commands map to MCP tools (e.g., `proxy list` → `proxy_list`)
- CLI is a thin client - all logic lives in MCP tool handlers
- New features should be implemented in MCP handlers first, CLI wraps them

### CLI Conventions

- All list operations must support `--limit` flag
- Flatten `--help` details at the first subcommand level
- CLI requires running MCP server; error message guides user to start it

### Documentation

- `sidecar/README.md` documents both the Go SDK and the JSON-RPC 2.0 wire protocol. Keep it in sync with any sidecar API or SDK change: wire method/params/result shapes, error codes, capabilities, versioning behavior, or exported SDK surface. A non-SDK author relies on it, so treat it as part of the contract, not an afterthought.

### Code Style

- Use `var` style for zero-value initialization: `var foo bool` not `foo := false`
- Comments should be concise simple and short phrases rather than full sentences when possible
- Comments should only be added when they describe non-obvious context, not a single line of code
- Godocs should only describe the inputs and outputs, not how the function works
- Follow existing naming conventions and neighboring code style

### Collection handling

Reach for stdlib `slices`/`maps`/`strings` and `github.com/go-analyze/bulk` before writing a manual loop. The patterns below come up often:

- **Clone a slice or map**: `slices.Clone(src)` / `maps.Clone(src)`. Do not `make([]T, len(src))` + `copy(dst, src)` for whole-slice clones (`copy` is still correct for sub-slice writes into an existing buffer).
- **Filter a slice (same element type, no transformation)**: `bulk.SliceFilter(predicate, s)`. Use `bulk.SliceFilterInPlace` when the caller doesn't reuse the input backing array. Use instead of `for _, v := range s { if cond { out = append(out, v) } }`.
- **Slice → map set**: `bulk.SliceToSet(s)` (returns `map[T]struct{}`). Membership tests use the comma-ok form: `if _, ok := set[k]; ok`.
- **Map → slice of keys / values**: `bulk.MapKeysSlice(m)` and `bulk.MapValuesSlice(m)`. Don't write `for k := range m { keys = append(keys, k) }`.
- **Membership check on a slice**: `slices.Contains(s, x)` for comparable element types, `slices.ContainsFunc(s, predicate)` for everything else.
- **Sort a slice with a custom comparator**: `slices.SortFunc(s, cmp)` / `slices.SortStableFunc(s, cmp)`. Use instead of `sort.Slice` / `sort.SliceStable`.

### Testing

Structure and conventions:
- One `_test.go` file per implementation file that requires testing
- One `func Test<FunctionName>` per target function, using table-driven tests or `t.Run` cases
- Test case names should be at most 3 to 5 words and in lower case with underscores
- Use `t.Parallel()` at test function start when no shared state, but not in the test cases
- Isolated temp directories via `t.TempDir()` when needed
- Context timeouts via `t.Context()` for tests with I/O

Assertions and validation:
- Assertions rely on `testify` (`require` for setup, `assert` for assertions)
- Don't include messages unless the message provides context outside of the test point
- Do NOT use time.Sleep for tests, instead use require.Eventually or deterministic triggers

Test helpers:
- Mock MCP server available via `service.NewTestMCPServer()`
- Test utilities in `sectool/service/testutil/`

Verification:
- Always verify with `make test-all` and `make lint` before considering changes complete
