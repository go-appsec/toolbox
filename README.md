<img width="400" height="160" alt="go-appsec/toolbox" src="https://github.com/user-attachments/assets/00d3aa0d-68ef-471a-a5d7-07d3b4db7455" />

[![license](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/go-appsec/toolbox/blob/main/LICENSE)
[![Build Status](https://github.com/go-appsec/toolbox/actions/workflows/tests-main.yml/badge.svg)](https://github.com/go-appsec/toolbox/actions/workflows/tests-main.yml)

**MCP-based application security testing tools for your coding agent.**

Not a scanner — a collaborative workbench. Agents struggle with UI and stateful APIs; you're good at both. Sectool bridges the gap by exposing stable primitives — proxy history, replay, crawling, OAST, diffing — so AppSec engineers and pentesters can explore apps and validate reports augmented by an agent.

You handle auth and UI interactions, the agent queries flows, mutates requests, finds reflections, and attempts other permutations. Combining your abilities makes routine tasks easier, hidden indicators less likely to be missed, and complex testing more thorough.

## Getting Started

### 1. Install sectool

```bash
go install github.com/go-appsec/toolbox/sectool@latest
```

**No Go?** Download the binary for your platform (Linux, macOS, Windows — amd64 and arm64) from the [latest release](https://github.com/go-appsec/toolbox/releases).

### 2. Start the MCP (Model Context Protocol) server

```bash
sectool mcp
```

This starts an MCP server on port 9119 with a built-in HTTP proxy on port 8080.

### 3. Configure your browser

Point your browser's proxy settings at `127.0.0.1:8080` (or the port specified with `--proxy-port`).

For HTTPS interception, install the CA certificate from `~/.sectool/ca.pem` (auto-generated on first run). Most browsers accept it through their certificate settings; on macOS you can also add it to the system keychain.

**Using Burp?** Follow [Burp's proxy configuration](https://portswigger.net/burp/documentation/desktop/external-browser-config) instead, then start sectool with `sectool mcp --burp`.

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

**Native (default):** Built-in proxy with wire-fidelity and HTTP/1.1, HTTP/2, and WebSocket support. Designed to be as capable as Burp for MITM testing. A single binary provides the MCP server, proxy, and CLI — fully self-contained and usable in headless environments.

**Burp (optional):** If you prefer a GUI to review the agent's actions or already have Burp running, install the MCP extension from the BApp Store and ensure the MCP server runs on `http://127.0.0.1:9876/`.

| Option | Description |
|--------|-------------|
| (default) | Auto-detect: tries Burp MCP first, falls back to native proxy |
| `--proxy-port 8080` | Force native proxy on specified port |
| `--burp` | Force Burp MCP (fails if unavailable) |

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

The CLI shares state with the agent and provides a human-friendly interface for reviewing, replaying, and scripting. All commands are also available as MCP tools, state shared with the agent.

```bash
# Review what the proxy captured while you browsed
sectool proxy summary
sectool proxy list --host example.com
sectool proxy cookies --name session_id

# Crawl an app to discover endpoints and forms
sectool crawl create --url https://example.com
sectool crawl summary <session_id>

# Replay a captured request with modifications
sectool replay send --flow <flow_id> --add-header "X-Test: value"

# Set up out-of-band interaction testing and check for callbacks
sectool oast create
sectool oast poll <oast_id>
sectool oast get <oast_id> <event_id>

# Compare two flows, detect reflections, inspect JWTs
sectool diff <flow_a> <flow_b> --scope response
sectool reflected <flow_id>
sectool jwt <token>

# Export a flow, edit it offline, and resend
sectool proxy export <flow_id>
# ... edit ./sectool-requests/<flow_id>/request.http ...
sectool replay send --bundle <flow_id>
```

Use `sectool <command> --help` for detailed options.

## Key Features

- **Wire-fidelity proxy** - HTTP/1.1 and HTTP/2 MITM preserving header order, casing, and protocol anomalies — security testing needs exact bytes, not normalized rewrites
- **Replay with mutation** - Resend captured requests with selective edits to headers, body, query params, or JSON fields; pair with match/replace rules for iterative testing
- **Flow diffing** - Structured, content-type-aware comparison of two flows (JSON path-level, unified text, binary size) for fast report validation
- **Reflection detection** - Find request parameter values reflected in responses across multiple encoding variants to surface injection points
- **OAST** - Out-of-band interaction testing via Interactsh; create domains, poll for DNS/HTTP/SMTP callbacks
- **Crawling** - Discover endpoints, forms, and application structure; seed from proxy history or URLs
- **WebSocket support** - Frame-level interception, proxying, and match/replace for WebSocket messages
- **Workflow modes** - Task-specific agent guidance (explore, test-report) to improve collaboration quality and reduce token waste
- **Encoding utilities** - URL, Base64, HTML encoding/decoding, hashing (MD5/SHA/HMAC), JWT inspection
- **Burp Suite integration** - Optional GUI frontend via Burp MCP extension; or run fully headless with the native proxy
