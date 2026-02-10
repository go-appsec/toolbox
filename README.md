# go-appsec/toolbox

[![license](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/go-appsec/toolbox/blob/main/LICENSE)
[![Build Status](https://github.com/go-appsec/toolbox/actions/workflows/tests-main.yml/badge.svg)](https://github.com/go-appsec/toolbox/actions/workflows/tests-main.yml)

**MCP-based application security testing tools for your coding agent.**

Collaborative application security testing with coding agents. Sectool gives your agent the same tools you use — proxy history, request replay, crawling, out-of-band testing — via MCP (Model Context Protocol), allowing you to work together. You handle authentication or interact with the UI, the agent probes targets and analyzes responses, and attempts other permutations. Combining your abilities makes routine tasks easier, junior security engineers more capable, hidden indicators less likely to be missed, and complex testing more thorough.

## Getting Started

### 1. Install sectool

Download the binary for your platform (Linux, macOS, Windows — amd64 and arm64) from the [latest release](https://github.com/go-appsec/toolbox/releases), install with `go install`:

```bash
go install github.com/go-appsec/toolbox/sectool@latest
```

Or build from source:

```bash
git clone https://github.com/go-appsec/toolbox.git
cd toolbox
make build
```

### 2. Start the MCP server

```bash
sectool mcp
```

This starts an MCP server on port 9119 with a built-in HTTP proxy on port 8080.

### 3. Configure your browser

Note: These instructions are for the built-in proxy. If using [Burp Suite](https://portswigger.net/burp/communitydownload), follow [Burp's proxy configuration](https://portswigger.net/burp/documentation/desktop/external-browser-config) instead.

Point your browser's proxy settings at `127.0.0.1:8080` (or the port specified with `--proxy-port`).

For HTTPS interception, install the CA certificate from `~/.sectool/ca.pem`. The certificate is auto-generated on first run. Most browsers accept it through their certificate settings; on macOS you can also add it to the system keychain.

### 4. Connect your agent

**Claude Code:**
```bash
claude mcp add --transport http sectool http://127.0.0.1:9119/mcp
```

**Codex** (`~/.codex/config.toml`):
```toml
[mcp_servers.sectool]
url = "http://127.0.0.1:9119/mcp"
```

### 5. Collaborate

Work with the agent to build a test plan and execute it together. The agent can query proxy history, replay modified requests, crawl for endpoints, and test for out-of-band interactions while you handle browser-based actions like authentication or interacting with and reviewing the UI.

## Server Options

### Proxy backends

| Option | Description |
|--------|-------------|
| (default) | Auto-detect: tries Burp MCP first, falls back to built-in proxy |
| `--proxy-port 8080` | Force built-in proxy on specified port |
| `--burp` | Force Burp MCP (fails if unavailable) |

**Burp Suite (optional):** If you prefer your existing Burp setup or want a GUI to review the agent's actions, install the MCP extension from the BApp Store and ensure the MCP server runs on `http://127.0.0.1:9876/sse`.

**Native:** The native proxy is designed to be as capable (and in some cases more capable) than Burp for MITM testing, with precise wire-fidelity and HTTP/1.1, HTTP/2, and WebSocket support.

Both backends can also be reviewed and utilized through the CLI. With the native backend, the CLI is the only way to interact with proxy history directly.

### Workflow modes

Sectool automatically determines the appropriate workflow when the agent calls the `workflow` tool at the start of a session. You can skip this step and save tokens by specifying the workflow upfront:

```bash
sectool mcp                        # Default: agent selects task type via workflow tool
sectool mcp --workflow explore     # Pre-set exploration mode (token-optimized)
sectool mcp --workflow test-report # Pre-set validation mode (token-optimized)
sectool mcp --workflow none        # No workflow instructions
```

| Mode | Description |
|------|-------------|
| (default) | Agent selects task type by calling `workflow` tool, receives collaboration instructions |
| `explore` | Exploratory security testing; token-optimized, all tools available |
| `test-report` | Validating a specific vulnerability report; token-optimized, crawl tools excluded |
| `none` | No workflow instructions, all tools available immediately |

Workflow instructions guide agents toward collaborative testing rather than trying to do everything autonomously or stepping you through a process without adding value. If you have ideas for improving agent collaboration, [open an issue](https://github.com/go-appsec/toolbox/issues).

### MCP transports

The server exposes two endpoints:
- `/mcp` - Streamable HTTP (recommended)
- `/sse` - SSE (legacy, for older clients)

## CLI Usage

The CLI provides a human-friendly interface to the same tools that agents use. CLI commands require the MCP server to be running (`sectool mcp`).

```bash
# Proxy history
sectool proxy summary              # Aggregated traffic summary
sectool proxy list --host example  # List flows matching filter
sectool proxy export <flow_id>     # Export flow to ./sectool-requests/<flow_id>/
sectool proxy rule list            # List match/replace rules

# Crawling
sectool crawl create --url https://example.com
sectool crawl seed <session_id> --url https://example.com/other
sectool crawl status <session_id>
sectool crawl summary <session_id>
sectool crawl list <session_id>
sectool crawl forms <session_id>
sectool crawl errors <session_id>
sectool crawl export <flow_id>
sectool crawl sessions
sectool crawl stop <session_id>

# Replay requests
sectool replay send --flow <flow_id> --add-header "X-Test: value"
sectool replay get <replay_id>
sectool replay create              # Create request bundle from scratch

# Out-of-band testing
sectool oast create
sectool oast summary <oast_id>     # Aggregated interaction summary
sectool oast poll <oast_id>        # List individual events
sectool oast get <oast_id> <event_id>
sectool oast list
sectool oast delete <oast_id>

# Encoding utilities
sectool encode url "hello world"
sectool encode base64 "test"
sectool encode html "<script>"
```

Use `sectool <command> --help` for detailed options.

## Key Features

- **Burp Suite integration** - Use your existing Burp setup instead of the built-in proxy
- **Wire-fidelity proxy** - HTTP/1.1 and HTTP/2 MITM preserving header order, casing, and protocol anomalies for security testing
- **WebSocket interception** - Frame-level proxying and match/replace for WebSocket messages
- **Match/replace rules** - Modify requests, responses, and WebSocket messages in transit
- **Request replay** - Replay captured requests with modifications to headers, body, query params, or JSON fields
- **Web crawling** - Discover application structure, forms, and endpoints
- **OAST testing** - Create out-of-band domains and poll for DNS/HTTP/SMTP interactions via Interactsh
- **Encoding utilities** - URL, Base64, and HTML entity encoding/decoding
