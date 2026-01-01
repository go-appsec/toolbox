# llm-security-toolbox

An LLM-first security testing toolkit that enables coding agents to collaborate with you on security testing. Sectool provides two integration modes—MCP API for direct tool calls or CLI with system prompts—letting you brainstorm with an agent, validate security reports together, or have the agent probe vulnerabilities in parallel with your own testing.

## Project Status

Early development, but usable! Current plans:

1. **Evaluate CLI and MCP interfaces** — We suspect both will be retained long-term, but need more testing to confirm.
2. **Refactor once the agent interface is well-designed** — The current code design is an artifact of prototype iterations.
3. **Pre-compiled binaries after stabilization** — Until then, `make build` is required to use this project.

We will keep adding features (see [Issues](https://github.com/go-harden/llm-security-toolbox/issues) for planned work) with the goal of enabling a highly collaborative security agent experience.

Questions or recommendations? Please [open an Issue](https://github.com/go-harden/llm-security-toolbox/issues)!

## Getting Started

### 1. Install sectool

Download the binary for your platform from the [latest release](https://github.com/go-harden/llm-security-toolbox/releases), or build from source:

```bash
git clone https://github.com/go-harden/llm-security-toolbox.git
cd llm-security-toolbox
make build
```

### 2. Set up Burp Suite with MCP

Install [Burp Suite Community](https://portswigger.net/burp/communitydownload) and add the MCP extension from the BApp Store.

Start Burp and ensure the MCP server is running on `http://127.0.0.1:9876/sse`. It's best if your burp session starts fresh without a proxy history for when starting with your agent.

> Note: Burp MCP is currently required. A built-in proxy is planned for future releases ([#3](https://github.com/go-harden/llm-security-toolbox/issues/3)).

### 3. Choose your integration mode

#### Option A: MCP Mode (Recommended)

Run sectool as an MCP server for direct tool integration:

```bash
sectool --mcp
```

This starts an SSE server on port 9119. Configure your agent:

**Claude Code:**
```bash
claude mcp add --transport sse sectool http://127.0.0.1:9119/sse
```

**Codex** (`.codex/config.yaml`):
```yaml
mcp_servers:
  - name: sectool
    url: http://127.0.0.1:9119/sse
```

MCP mode is more token-efficient and works system-wide across agent sessions.

#### Option B: CLI Mode with System Prompts

Initialize a working directory with agent-specific system prompts:

```bash
sectool init test-report   # Validate a known security report
sectool init explore       # Broader exploratory security testing
```

Start your agent with the generated prompt:

```bash
claude --system-prompt-file .sectool/AGENT-explore.md
```

CLI mode is useful when:
- You want to invoke the CLI alongside the agent
- Editing large requests or performing complex request modifications
- Keeping the agent session isolated to a working directory

### 4. Collaborate on testing

Work with the agent to build a test plan and execute it together. The agent can query proxy history, replay modified requests, and test for out-of-band interactions while you handle browser-based actions like authentication.

## Key Features

- **Proxy history access** - Query and filter HTTP traffic captured through Burp Suite
- **Proxy rules** - Add match/replace rules to modify requests and responses in transit
- **Request export and replay** - Export requests to disk, edit them, and replay with modifications
- **OAST testing** - Create out-of-band domains and poll for DNS/HTTP/SMTP interactions via Interactsh
- **Encoding utilities** - URL, Base64, and HTML entity encoding/decoding
- **LLM-optimized** - Interactions optimized for agent usage
