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
- `sectool/service/mcp_proxy.go` - Proxy tool handlers (poll, get, cookie_jar, rules)
- `sectool/service/mcp_replay.go` - Replay tool handlers (send, get, request_send)
- `sectool/service/mcp_crawl.go` - Crawl tool handlers (create, seed, status, poll, get, sessions, stop)
- `sectool/service/mcp_oast.go` - OAST tool handlers (create, poll, get, list, delete)
- `sectool/service/mcp_encode.go` - Encode/decode tool handlers (url, base64, html)
- `sectool/service/mcp_hash.go` - Hash tool handler (md5, sha1, sha256, sha512, HMAC)
- `sectool/service/mcp_jwt.go` - JWT decode tool handler
- `sectool/service/mcp_diff.go` - Diff tool handler (structured flow comparison)
- `sectool/service/mcp_reflection.go` - Reflection tool handler (parameter reflection detection)
- `sectool/service/flags.go` - MCP server flag parsing (`--port`, `--workflow`, `--config`)
- `sectool/service/backend.go` - HttpBackend, OastBackend, CrawlerBackend interfaces
- `sectool/service/backend_http_native.go` - Native built-in proxy implementation of HttpBackend
- `sectool/service/backend_http_burp.go` - Burp MCP implementation of HttpBackend
- `sectool/service/backend_oast_interactsh.go` - Interactsh implementation of OastBackend
- `sectool/service/backend_crawler_colly.go` - Colly-based crawler implementation
- `sectool/service/capture_filter.go` - BuildCaptureFilter: compiles proxy exclusion patterns from config
- `sectool/service/httputil.go` - HTTP request/response parsing utilities
- `sectool/service/jsonutil.go` - JSON field modification utilities
- `sectool/service/types.go` - Service-specific request and internal types

### Proxy Package

- `sectool/service/proxy/types.go` - Core types (Header, RawHTTP1Request/Response, H2RequestData/Response, HistoryEntry, Target, RuleApplier)
- `sectool/service/proxy/parser.go` - HTTP/1.1 tolerant parser with wire fidelity
- `sectool/service/proxy/validate.go` - Optional request validation
- `sectool/service/proxy/server.go` - TCP listener, accept loop, protocol detection
- `sectool/service/proxy/handler_http1.go` - Plain HTTP and HTTP-over-TLS handler
- `sectool/service/proxy/handler_connect.go` - CONNECT tunnel and TLS MITM with ALPN negotiation
- `sectool/service/proxy/handler_http2.go` - HTTP/2 stream handler with HPACK
- `sectool/service/proxy/handler_websocket.go` - WebSocket frame proxying
- `sectool/service/proxy/cert.go` - CA and per-hostname certificate management
- `sectool/service/proxy/history.go` - Thread-safe history storage
- `sectool/service/proxy/filter.go` - CaptureFilter type, SetCaptureFilter/ShouldCapture
- `sectool/service/proxy/compression.go` - gzip/deflate utilities
- `sectool/service/proxy/sender.go` - Wire-fidelity request sender (H1 and H2)
- `sectool/service/proxy/httputil.go` - HTTP method extraction, header grouping, and raw query modification utilities
- `sectool/service/proxy/hpack.go` - HPACK encoder/decoder management

### Burp MCP Client

- `sectool/service/mcp/burp.go` - SSE-based Burp Suite MCP client
- `sectool/service/mcp/types.go` - MCP-specific types

### State Management

- `sectool/service/store/storage.go` - Storage interface and in-memory implementation
- `sectool/service/store/spill.go` - SpillStore: disk-paging Storage with LRU eviction, encryption, and compaction
- `sectool/service/store/serialize.go` - Msgpack serialization helpers
- `sectool/service/store/proxy_index.go` - Bidirectional flow_id ↔ proxy offset mapping
- `sectool/service/store/replay_history.go` - Replay request/response storage with meta/payload split
- `sectool/service/ids/ids.go` - Base62 random IDs using crypto/rand

### CLI Commands

- `sectool/proxy/flags.go` - Subcommand parsing (summary/list/cookies/export/rule)
- `sectool/proxy/list.go` - List/summary command implementation
- `sectool/proxy/cookies.go` - Cookies command implementation
- `sectool/proxy/export.go` - Export command implementation
- `sectool/proxy/rule.go` - Rule CRUD command implementations
- `sectool/crawl/flags.go` - Crawl subcommand parsing
- `sectool/crawl/crawl.go` - Crawl command implementations
- `sectool/replay/flags.go` - Subcommand parsing (send/get)
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

### Config

Global config at `~/.sectool/config.json` (auto-created with defaults):

```json
{
  "mcp_port": 9119,
  "burp_required": false,
  "max_body_bytes": 10485760,
  "include_subdomains": true,
  "allowed_domains": [],
  "exclude_domains": [],
  "proxy": {
    "exclude_extensions": "<RE2 alternation, see DefaultExcludeExtensions>"
  },
  "crawler": {
    "disallowed_paths": ["*logout*", "*signout*", "*sign-out*", "*delete*", "*remove*"],
    "delay_ms": 200,
    "parallelism": 2,
    "max_depth": 10,
    "max_requests": 1000,
    "extract_forms": true,
    "submit_forms": false,
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

### Export Bundle Layout

Bundles at `./sectool-requests/<flow_id>/`: `request.http` (headers + body placeholder), `body` (raw binary-safe), `request.meta.json` (method/URL/timestamps), `response.http`, `response.body`

## Key Types

**Backend Interfaces (`sectool/service/backend.go`):**
- `HttpBackend` - proxy history (get/regex), request sending, match/replace rules CRUD
- `OastBackend` - OAST session create/delete, event polling, session listing
- `CrawlerBackend` - crawl session lifecycle and result retrieval

**Store (`sectool/service/store/`):**
- `Storage` - key-value blob interface (`memStorage`, `SpillStore` disk-paging)
- `ProxyIndex` - bidirectional flow_id ↔ proxy offset mapping
- `ReplayHistoryStore` - replay storage with meta/payload split

## MCP Tools

**MCP server:** `sectool mcp [--proxy-port PORT] [--burp] [--port PORT] [--workflow MODE]` (default port 9119, auto-detects backend)

- `workflow` - select mode (explore/test-report) for task-specific instructions
- `proxy_poll` - query proxy history: summary or list with filters
- `proxy_get` - full request/response for a flow
- `cookie_jar` - extract and deduplicate cookies; overview without filters, full values and JWT decode with name/domain filter
- `proxy_rule_list` - list match/replace rules
- `proxy_rule_add` - add match/replace rule
- `proxy_rule_delete` - delete rule
- `crawl_create` - start crawl from URLs or proxy flow seeds
- `crawl_seed` - add seeds to running crawl
- `crawl_status` - crawl progress metrics
- `crawl_poll` - query results: summary, flows, forms, or errors
- `crawl_get` - full request/response for crawled flow
- `crawl_sessions` - list all crawl sessions
- `crawl_stop` - stop a running crawl session
- `replay_send` - send with modifications (headers, body, JSON, query params)
- `replay_get` - retrieve replay response
- `request_send` - send new HTTP request from scratch
- `oast_create` - create OAST session for out-of-band testing
- `oast_poll` - poll events: summary or list
- `oast_get` - full details of specific OAST event
- `oast_list` - list active OAST sessions
- `oast_delete` - delete OAST session
- `encode` - encode a string (url, base64, html)
- `decode` - decode a string (url, base64, html)
- `hash` - compute hash digest (md5, sha1, sha256, sha512, HMAC)
- `jwt_decode` - decode and inspect JWT tokens
- `diff_flow` - compare two captured flows with structured, content-type-aware diffing
- `find_reflected` - detect request parameter values reflected in the response

## CLI Commands

CLI requires a running MCP server. Maps to MCP tools via `sectool <module> <sub>` pattern.

- `proxy`: `summary`, `list`, `cookies`, `export`, `rule {add,delete,list}`
- `crawl`: `create`, `seed`, `status`, `summary`, `list`, `export`, `sessions`, `stop`
- `replay`: `send`, `get`
- `oast`: `create`, `summary`, `poll`, `list`, `delete`
- `encode`: `url`, `base64`, `html`
- `decode`: `url`, `base64`, `html`
- `hash`: compute hash digests
- `jwt`: decode JWT tokens
- `diff`: `<flow_a> <flow_b> --scope <scope>`
- `reflected`: `<flow_id>`
- `version`

## Development Guidelines

### CLI and MCP Parity

- CLI commands map to MCP tools (e.g., `proxy list` → `proxy_list`)
- CLI is a thin client - all logic lives in MCP tool handlers
- New features should be implemented in MCP handlers first, CLI wraps them

### CLI Conventions

- All list operations must support `--limit` flag
- Flatten `--help` details at the first subcommand level
- CLI requires running MCP server; error message guides user to start it

### Code Style

- Use `var` style for zero-value initialization: `var foo bool` not `foo := false`
- Comments should be concise simple and short phrases rather than full sentences when possible
- Comments should only be added when they describe non-obvious context
- Follow existing naming conventions and neighboring code style

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

Test helpers:
- Mock MCP server available via `service.NewTestMCPServer()`
- Test utilities in `sectool/service/testutil/`

Verification:
- Always verify with `make test-all` and `make lint` before considering changes complete
