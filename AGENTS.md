## Project Overview

**llm-security-toolbox (sectool)** is an LLM-first CLI toolkit for application security testing. It enables humans and agentic coding tools to collaborate on security testing, backed by Burp Suite Pro via PortSwigger MCP (Model Context Protocol).

Key characteristics:
- MCP-primary architecture: single API serves both agents and CLI
- CLI is a thin client over MCP for human interaction
- Global config at `~/.sectool/config.json` (auto-created on first run)
- All output in markdown format for LLM consumption
- Pluggable backend architecture (Burp MCP for HTTP, Interactsh for OAST, Colly for crawling)

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
CLI Command → MCP Client → MCP Server → Backends (Burp MCP, OAST, Crawler)
MCP Agent  → MCP Server → Backends (Burp MCP, OAST, Crawler)
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
- `sectool/service/mcp_proxy.go` - Proxy tool handlers (poll, get, rules)
- `sectool/service/mcp_replay.go` - Replay tool handlers (send, get, request_send)
- `sectool/service/mcp_crawl.go` - Crawl tool handlers (create, seed, status, poll, get, sessions, stop)
- `sectool/service/mcp_oast.go` - OAST tool handlers (create, poll, get, list, delete)
- `sectool/service/mcp_encode.go` - Encode tool handlers (url, base64, html)
- `sectool/service/flags.go` - MCP server flag parsing (`--port`, `--workflow`, `--config`)
- `sectool/service/backend.go` - HttpBackend, OastBackend, CrawlerBackend interfaces
- `sectool/service/backend_http_burp.go` - Burp MCP implementation of HttpBackend
- `sectool/service/backend_oast_interactsh.go` - Interactsh implementation of OastBackend
- `sectool/service/backend_crawler_colly.go` - Colly-based crawler implementation
- `sectool/service/httputil.go` - HTTP request/response parsing utilities
- `sectool/service/jsonutil.go` - JSON field modification utilities
- `sectool/service/types.go` - Service-specific request and internal types

### Burp MCP Client

- `sectool/service/mcp/burp.go` - SSE-based Burp Suite MCP client
- `sectool/service/mcp/types.go` - MCP-specific types

### State Management

- `sectool/service/store/flow.go` - Flow ID → Burp offset mapping (ephemeral)
- `sectool/service/store/crawl_flow.go` - Crawler flow storage (ephemeral)
- `sectool/service/store/hash.go` - Content hashing for flow identity
- `sectool/service/store/request.go` - Replay result storage with TTL cleanup
- `sectool/service/ids/ids.go` - Base62 random IDs using crypto/rand

### CLI Commands

- `sectool/proxy/flags.go` - Subcommand parsing (summary/list/export/rule)
- `sectool/proxy/list.go` - List/summary command implementation
- `sectool/proxy/export.go` - Export command implementation
- `sectool/proxy/rule.go` - Rule CRUD command implementations
- `sectool/crawl/flags.go` - Crawl subcommand parsing
- `sectool/crawl/crawl.go` - Crawl command implementations
- `sectool/replay/flags.go` - Subcommand parsing (send/get)
- `sectool/replay/replay.go` - Command implementations
- `sectool/oast/flags.go` - Subcommand parsing (create/poll/list/delete)
- `sectool/oast/oast.go` - Command implementations
- `sectool/encode/flags.go` - Subcommand parsing (url/base64/html)
- `sectool/encode/encode.go` - Encoding/decoding implementations

### Config

Global config at `~/.sectool/config.json` (auto-created with defaults):

```json
{
  "version": "0.0.1",
  "mcp_port": 9119,
  "crawler": {
    "max_response_body_bytes": 1048576,
    "include_subdomains": true,
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

### Export Bundle Layout

Bundles exported to `./sectool-requests/<flow_id>/`:

```
./sectool-requests/<flow_id>/
├── request.http       # HTTP headers with body placeholder
├── body               # Raw request body (binary-safe)
├── request.meta.json  # Metadata (method, URL, timestamps)
├── response.http      # Response headers (if available)
└── response.body      # Response body (if available)
```

## Key Types

**Backend Interfaces (service/backend.go):**
```go
// HttpBackend abstracts proxy history and request sending
type HttpBackend interface {
    GetProxyHistory(ctx context.Context, count, offset int) ([]ProxyHistoryEntry, error)
    GetProxyHistoryRegex(ctx context.Context, regex string, count, offset int) ([]ProxyHistoryEntry, error)
    SendRequest(ctx context.Context, req SendRequestParams) (*SendRequestResult, error)
    Close() error
}

// OastBackend abstracts out-of-band testing
type OastBackend interface {
    CreateSession(ctx context.Context) (*OastSession, error)
    PollEvents(ctx context.Context, sessionID string, since string, wait time.Duration) ([]OastEvent, error)
    ListSessions(ctx context.Context) ([]*OastSession, error)
    DeleteSession(ctx context.Context, sessionID string) error
    Close() error
}
```

**Store Types (service/store/):**
- `FlowStore`: Maps short flow_id → Burp offset with hash-based re-identification
- `CrawlFlowStore`: Stores crawler flow data
- `RequestStore`: Stores replay results with TTL cleanup

## CLI Commands

Start MCP server:
```bash
sectool mcp                    # MCP server on port 9119
sectool mcp --port 8080        # Custom port
sectool mcp --workflow explore # Pre-set workflow mode
```

CLI commands (requires running MCP server):
```bash
sectool proxy summary        # Aggregated traffic summary by host/path/method
sectool proxy list           # List individual flows (requires filters)
sectool proxy export         # Export flow to editable bundle on disk

sectool crawl create         # Start new crawl session from URLs or proxy flows
sectool crawl status         # Check crawl session progress
sectool crawl summary        # Aggregated crawl results by host/path
sectool crawl list           # List crawled flows, forms, or errors
sectool crawl export         # Export crawled flow to editable bundle
sectool crawl sessions       # List all crawl sessions
sectool crawl stop           # Stop running crawl session

sectool replay send          # Send request (from flow, bundle, or file)
sectool replay get           # Retrieve replay result by ID

sectool oast create          # Create OAST session, returns domain
sectool oast summary         # Aggregated OAST events by subdomain/source_ip/type
sectool oast poll            # Poll for out-of-band interactions
sectool oast list            # List active OAST sessions
sectool oast delete          # Delete OAST session

sectool encode url           # URL encode/decode
sectool encode base64        # Base64 encode/decode
sectool encode html          # HTML entity encode/decode

sectool version              # Show version
```

## MCP Tools

When running in MCP mode, the following tools are exposed:

| Tool | Description |
|------|-------------|
| `workflow` | Select workflow mode (explore/test-report) to receive task-specific instructions |
| `proxy_poll` | Query proxy history: summary (default) or list mode with filters |
| `proxy_get` | Get full request/response for a flow |
| `proxy_rule_list` | List proxy match/replace rules |
| `proxy_rule_add` | Add proxy match/replace rule |
| `proxy_rule_update` | Update existing proxy rule |
| `proxy_rule_delete` | Delete proxy rule |
| `crawl_create` | Start crawl session from URLs or proxy flow seeds |
| `crawl_seed` | Add additional seed URLs or proxy flows to a running crawl session |
| `crawl_status` | Get crawl session progress metrics |
| `crawl_poll` | Query crawl results: summary (default), flows, forms, or errors |
| `crawl_get` | Get full request/response for a crawled flow |
| `crawl_sessions` | List all crawl sessions |
| `crawl_stop` | Stop a running crawl session |
| `replay_send` | Send request with modifications (headers, body, JSON fields, query params) |
| `replay_get` | Retrieve full response from previous replay |
| `request_send` | Send a new HTTP request from scratch |
| `oast_create` | Create OAST session for out-of-band testing |
| `oast_poll` | Poll for OAST events: summary (default) or list mode |
| `oast_get` | Get full details of specific OAST event |
| `oast_list` | List active OAST sessions |
| `oast_delete` | Delete OAST session |
| `encode_url` | URL encode/decode |
| `encode_base64` | Base64 encode/decode |
| `encode_html` | HTML entity encode/decode |

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
- Use `t.Parallel()` at test function start when no shared state
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
