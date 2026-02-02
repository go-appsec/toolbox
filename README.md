# go-appsec/llm-security-toolbox

[![license](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/go-appsec/llm-security-toolbox/blob/main/LICENSE)
[![Build Status](https://github.com/go-appsec/llm-security-toolbox/actions/workflows/tests-main.yml/badge.svg)](https://github.com/go-appsec/llm-security-toolbox/actions/workflows/tests-main.yml)

An LLM-first security testing toolkit that enables coding agents to collaborate with you on security testing. Sectool exposes security testing tools via MCP (Model Context Protocol), letting you brainstorm with an agent, validate security reports together, or have the agent probe vulnerabilities in parallel with your own testing.

## Project Status

Early development, but usable! Current plans:

1. **Stabilize the MCP interface** — Active iteration based on agent feedback.
2. **Refactor once the agent interface is well-designed** — The current code design is an artifact of prototype iterations.
3. **Pre-compiled binaries after stabilization** — Until then, `make build` is required to use this project.

We will keep adding features (see [Issues](https://github.com/go-appsec/llm-security-toolbox/issues) for planned work) with the goal of enabling a highly collaborative security agent experience.

Questions or recommendations? Please [open an Issue](https://github.com/go-appsec/llm-security-toolbox/issues)!

## Getting Started

### 1. Install sectool

Download the binary for your platform from the [latest release](https://github.com/go-appsec/llm-security-toolbox/releases), or build from source:

```bash
git clone https://github.com/go-appsec/llm-security-toolbox.git
cd llm-security-toolbox
make build
```

### 2. Start the MCP server

Run sectool as an MCP server:

```bash
sectool mcp
```

This starts an MCP server on port 9119 with two endpoints:
- `/mcp` - Streamable HTTP transport (recommended)
- `/sse` - SSE transport (legacy, for older clients)

**Proxy backends:**

| Option | Description |
|--------|-------------|
| (default) | Auto-detect: tries Burp MCP first, falls back to built-in proxy |
| `--proxy-port 8080` | Force built-in proxy on specified port |
| `--burp` | Force Burp MCP (fails if unavailable) |

**Built-in proxy** - A wire-fidelity HTTP proxy designed for security testing:
- HTTP/1.1 and HTTP/2 MITM with automatic ALPN negotiation
- WebSocket interception at the frame level
- Header order and casing preserved exactly (critical for smuggling/WAF bypass tests)
- Protocol anomalies preserved (CL+TE, bare LF, obs-fold)
- Match/replace rules for requests, responses, and WebSocket messages
- Request replay with modifications (headers, body, query params)
- Compression handled transparently (gzip, deflate)
- CA certificate auto-generated at `~/.sectool/ca.pem`

**Burp Suite (optional)** - Use your existing Burp setup instead of the built-in proxy. Install [Burp Suite Community](https://portswigger.net/burp/communitydownload), add the MCP extension from the BApp Store, and ensure the MCP server runs on `http://127.0.0.1:9876/sse`. Sectool auto-detects and prefers Burp when available.

**Workflow modes:** Use `--workflow` to configure how the agent receives testing instructions:

```bash
sectool mcp                        # Default: agent selects task type via workflow tool
sectool mcp --workflow explore     # Pre-set exploration mode (token-optimized)
sectool mcp --workflow test-report # Pre-set validation mode (token-optimized)
sectool mcp --workflow none        # No workflow instructions
```

| Mode | Description |
|------|-------------|
| (default) | Agent decides task type by calling `workflow` tool first, receives collaboration instructions, all tools available |
| `explore` | Exploratory security testing; token-optimized (no tool call needed), all tools available |
| `test-report` | Validating a specific vulnerability report; token-optimized, crawl tools excluded |
| `none` | No workflow instructions, all tools available immediately |

Agents generally want to do everything for you (sometimes poorly), or step you through a process without adding much value. Our workflow instructions guide a more collaborative approach that strikes a balance between these extremes, while focusing instruction tokens on specific task goals. If the default behavior doesn't work for you, try `--workflow none` and [open an issue](https://github.com/go-appsec/llm-security-toolbox/issues) describing your experience or recommendations.

### 3. Configure your browser (built-in proxy only)

When using the built-in proxy, configure your browser to use `127.0.0.1:8080` (or your specified `--proxy-port`). For HTTPS interception, install the CA certificate from `~/.sectool/ca.pem`.

If using Burp Suite, configure your browser through Burp's proxy settings instead.

### 4. Configure your agent

**Claude Code:**
```bash
claude mcp add --transport http sectool http://127.0.0.1:9119/mcp
```

**Codex** (`~/.codex/config.toml`):
```toml
[mcp_servers.sectool]
url = "http://127.0.0.1:9119/mcp"
```

### 5. Collaborate on testing

Work with the agent to build a test plan and execute it together. The agent can query proxy history, replay modified requests, and test for out-of-band interactions while you handle browser-based actions like authentication.

## CLI Usage

The CLI provides a human-friendly interface to the same MCP tools that agents use. CLI commands require the MCP server to be running (`sectool mcp`).

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
sectool oast poll <oast_id>
sectool oast get <event_id>
sectool oast list
sectool oast delete <oast_id>

# Encoding utilities
sectool encode url "hello world"
sectool encode base64 "test"
sectool encode html "<script>"
```

Use `sectool <command> --help` for detailed options.

## Key Features

- **Wire-fidelity proxy** - HTTP/1.1 and HTTP/2 MITM preserving header order, casing, and protocol anomalies for security testing
- **Proxy history** - Query and filter traffic captured through built-in proxy or Burp Suite
- **Match/replace rules** - Modify requests, responses, and WebSocket messages in transit
- **Request replay** - Replay requests with modifications to headers, body, query params, or JSON fields
- **Web crawling** - Discover application structure, forms, and endpoints
- **OAST testing** - Create out-of-band domains and poll for DNS/HTTP/SMTP interactions via Interactsh
- **Encoding utilities** - URL, Base64, and HTML entity encoding/decoding
- **LLM-optimized** - Interactions and output formats designed for agent collaboration
