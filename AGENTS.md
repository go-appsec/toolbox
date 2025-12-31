## Project Overview

**llm-security-toolbox (sectool)** is an LLM-first CLI toolkit for application security testing. It enables humans and agentic coding tools to collaborate on security testing, backed by Burp Suite Pro via PortSwigger MCP (Model Context Protocol).

Key characteristics:
- Client-server architecture with automatic background service management
- Unix socket-based IPC (HTTP/JSON protocol)
- Per-working-directory service instances (state in `.sectool/`)
- All output in markdown format for LLM consumption
- Pluggable backend architecture (Burp MCP for HTTP, Interactsh for OAST)

## Build Commands

```bash
make build          # Build to bin/sectool
make build-cross    # Cross-compile (linux/darwin, amd64/arm64)
make test           # Quick tests (-short flag)
make test-all       # Full tests with -race and coverage
make test-cover     # Generate HTML coverage report (test.out)
make lint           # Run golangci-lint and go vet
```

## Architecture

| File | Description |
|------|-------------|
| `main.go` | Entry point; routes --service flag to daemon mode, else CLI command parsing and dispatch |
| `config/config.go` | Config loading/saving, defaults |
| `config/config_test.go` | Config tests |
| `service/server.go` | HTTP server over Unix socket |
| `service/client.go` | Auto-starts service if needed |
| `service/types.go` | Shared API types (ServicePaths, APIResponse, APIError) |
| `service/flags.go` | Service subcommand parsing |
| `service/commands.go` | Service CLI implementations (status/stop/logs) |
| `service/backend.go` | HttpBackend and OastBackend interface definitions |
| `service/backend_http_burp.go` | Burp MCP implementation of HttpBackend |
| `service/backend_oast_interactsh.go` | Interactsh implementation of OastBackend |
| `service/proxy_handler.go` | Handles /proxy/list, /proxy/export |
| `service/replay_handler.go` | Handles /replay/send, /replay/get |
| `service/oast_handler.go` | Handles /oast/* endpoints |
| `service/httputil.go` | HTTP parsing utilities |
| `service/bundle.go` | Request bundle file operations |
| `service/mcp/burp.go` | SSE-based Burp Suite MCP client |
| `service/mcp/types.go` | MCP-specific types |
| `service/store/flow.go` | Flow ID → Burp offset mapping (thread-safe) |
| `service/store/hash.go` | Content hashing for flow identity |
| `service/store/request.go` | Replay result storage with TTL cleanup |
| `service/ids/ids.go` | Base62 random IDs using crypto/rand |
| `service/socket_security.go` | Secure listener wrapper, socket path validation |
| `service/socket_security_{linux,darwin,other}.go` | Peer credential verification (SO_PEERCRED/LOCAL_PEERCRED) |
| `proxy/flags.go` | Subcommand parsing (list/export/intercept/rule) |
| `proxy/proxy.go` | Shared client proxy utilities |
| `proxy/list.go` | List command implementation |
| `proxy/export.go` | Export command implementation |
| `proxy/rule.go` | Rule CRUD command implementations |
| `replay/flags.go` | Subcommand parsing (send/get) |
| `replay/replay.go` | Command implementations |
| `oast/flags.go` | Subcommand parsing (create/poll/list/delete) |
| `oast/oast.go` | Command implementations |
| `encode/flags.go` | Subcommand parsing (url/base64/html) |
| `encode/encode.go` | Encoding/decoding implementations |
| `initialize/flags.go` | Subcommand parsing (explore/test-report) |
| `initialize/init.go` | Initialization logic |
| `initialize/templates/AGENT-explore.md` | Embedded exploration guide |
| `initialize/templates/AGENT-test-report.md` | Embedded test-report guide |

**Service lifecycle:**
1. CLI command runs → client checks for existing service via socket
2. If no service, client spawns `sectool --service` as background daemon
3. Daemon acquires file lock on `.sectool/service/pid` (prevents duplicates)
4. Daemon connects to Burp MCP and starts OAST backend
5. All CLI commands communicate with daemon via Unix socket at `.sectool/service/socket`

**State directory layout (0700 permissions, peer UID validation on socket):**
```
.sectool/
├── config.json           # Version, BurpMCPURL, preserve_guides flag
├── AGENT-explore.md      # Generated guide (if init explore)
├── AGENT-test-report.md  # Generated guide (if init test-report)
├── service/
│   ├── pid               # PID file with exclusive flock
│   ├── socket            # Unix domain socket; validates peer UID on accept
│   └── log.txt           # Service logs (0600, append-only)
└── requests/             # Exported request bundles
    └── <bundle_id>/
        ├── request.http       # HTTP headers with body placeholder
        ├── body               # Raw request body
        ├── request.meta.json  # Metadata (method, URL, timestamps)
        ├── response.http      # Response headers (after replay)
        └── response.body      # Response body (after replay)
```

## Key Types

```go
// Service discovery paths (service/types.go)
type ServicePaths struct {
    WorkDir, ServiceDir, SocketPath, PIDPath, LogFile, RequestsDir string
}

// API response envelope
type APIResponse struct {
    OK    bool            `json:"ok"`
    Data  json.RawMessage `json:"data,omitempty"`
    Error *APIError       `json:"error,omitempty"`
}

// Error codes: SERVICE_UNAVAILABLE, BACKEND_ERROR, INVALID_REQUEST,
//              NOT_FOUND, INTERNAL_ERROR, TIMEOUT, VALIDATION_ERROR
```

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
- `RequestStore`: Stores replay results

## CLI Commands

Use `sectool <command> --help` for detailed options.

sectool init explore        # Generate exploration guide
sectool init test-report    # Generate test-report guide

sectool service status      # Service health and backend status
sectool service logs        # View service logs
sectool service stop        # Graceful shutdown

sectool proxy list          # Summary or filtered captured request listing
sectool proxy export        # Export flow to editable bundle on disk

sectool replay send         # Send request (from flow, bundle, or file)
sectool replay get          # Retrieve replay result by ID

sectool oast create         # Create OAST session, returns domain
sectool oast poll           # Poll for out-of-band interactions
sectool oast list           # List active OAST sessions
sectool oast delete         # Delete OAST session

sectool encode url          # URL encode/decode
sectool encode base64       # Base64 encode/decode
sectool encode html         # HTML entity encode/decode

sectool version             # Show version

## Service HTTP API

All endpoints over Unix socket at `.sectool/service/socket`:

| Endpoint | Description |
|----------|-------------|
| `GET /health` | Service health, version, backend status |
| `POST /srv/stop` | Graceful shutdown |
| `POST /proxy/list` | Query proxy history with filters |
| `POST /proxy/export` | Export flow to disk bundle |
| `POST /replay/send` | Send request, returns replay_id |
| `POST /replay/get` | Retrieve replay result by ID |
| `POST /oast/create` | Create OAST session |
| `POST /oast/poll` | Poll for OAST events |
| `POST /oast/list` | List active OAST sessions |
| `POST /oast/delete` | Delete OAST session |

## Development Guidelines

### CLI Conventions

- All list operations (`proxy list`, `oast list`, `oast poll`) must support `--limit` flag
- Flatten --help details at the first subcommand level (e.g., `sectool proxy --help` shows full docs for list/export)
- Second tier subcommand help flags also exist and must be kept in sync

### Code Style

- Use `var` style for zero-value initialization: `var foo bool` not `foo := false`
- Comments should be concise simple and short phrases rather than full sentences when possible
- Comments should only be added when they describe non-obvious context (skip comments when the code or line is very obvious)
- Follow existing naming conventions and neighboring code style

### Testing

- One `_test.go` file per implementation file that requires testing
- One `func Test<FunctionName>` per target function, using table-driven tests for consistent validation or `t.Run` test cases when assertions vary
- Test case names should be at most 3 to 5 words and in lower case with underscores
- Assertions rely on `testify` (`require` for setup, `assert` for assertions)
- With assertions don't include messages unless the message provides context outside of the test point, or the two variables being evaluated
- Always verify with `make test` and `make lint` before considering changes complete
- Isolated temp directories via `t.TempDir()`
- Context timeouts via `t.Context()`
- Mock MCP server available via `service/mcp.NewTestMCPServer()`
- Use `t.Parallel()` for independent tests
