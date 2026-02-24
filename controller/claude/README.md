# sectool Controller — Claude Agent SDK

Autonomous security exploration controller that uses two Claude instances:

- **Worker** — Claude Code connected to sectool's MCP server. Performs the actual
  security testing using proxy, replay, crawl, OAST, and analysis tools.
- **Orchestrator** — Standard Claude API call (no tools). Evaluates worker output
  each turn and decides whether to continue, pivot, report a finding, or stop.

## Prerequisites

- Python 3.10+
- Claude Code CLI installed and authenticated (`claude` must be on PATH)
- An Anthropic API key exported as `ANTHROPIC_API_KEY` (for the orchestrator)
- Go toolchain (for building sectool)

## Installation

```bash
cd controller/claude
pip install -r requirements.txt
```

## Usage

```bash
python controller.py \
  --prompt "The proxy is configured on port 8181. Explore https://target.example.com for security issues." \
  --proxy-port 8181 \
  --max-iterations 30 \
  --model sonnet \
  --verbose
```

## CLI Arguments

| Flag | Required | Default | Description |
|------|----------|---------|-------------|
| `--prompt` | yes | — | Initial task prompt for the worker |
| `--proxy-port` | no | `8181` | Port for sectool's native proxy |
| `--mcp-port` | no | `9119` | Port for sectool's MCP server |
| `--findings-dir` | no | `./findings` | Directory for finding report files |
| `--max-iterations` | no | `30` | Hard cap on orchestrator loop iterations |
| `--max-cost` | no | none | USD cost ceiling; halts loop if exceeded |
| `--model` | no | `sonnet` | Model for the orchestrator (sonnet, opus, haiku) |
| `--worker-model` | no | none | Override model for the Claude Code worker |
| `--verbose` | no | false | Print full worker and orchestrator outputs |
| `--skip-build` | no | false | Skip `make build` (use existing binary) |
| `--workflow` | no | `explore` | Sectool workflow mode |
| `--external` | no | false | Connect to an already-running MCP server; skips build, server start, and teardown |

## Using with an Existing MCP Server

If you already have a sectool MCP server running (e.g. started manually or in
another terminal), use `--external` to skip the build and server lifecycle:

```bash
# Start the MCP server separately
bin/sectool mcp --proxy-port 8181 --workflow=explore

# In another terminal, run the controller against it
python controller.py \
  --prompt "Explore https://target.example.com for auth vulnerabilities." \
  --external \
  --proxy-port 8181 \
  --mcp-port 9119
```

The `--external` flag:
- Skips `make build` (no Go toolchain required)
- Does not start or stop the MCP server subprocess
- Connects directly to the server at `--mcp-port` (default 9119)
- Useful when running the proxy with custom flags, debugging the server, or
  connecting to a remote instance

## How It Works

1. **Build** — Runs `make build` to produce `bin/sectool`.
2. **Launch MCP server** — Starts `bin/sectool mcp` as a subprocess with the
   configured proxy port and workflow mode.
3. **Connect worker** — Creates a `ClaudeSDKClient` pointed at the MCP server
   with read-only repo access (Read, Glob, Grep, Bash) and all sectool tools.
4. **Initial prompt** — Sends the user's prompt to the worker.
5. **Orchestrator loop** — Each iteration:
   - Collects the worker's output (text and tool usage).
   - Sends a summary to the orchestrator for evaluation.
   - The orchestrator responds with one of:
     - `CONTINUE` — worker is on track, keep going.
     - `EXPAND` — pivot the plan based on new information.
     - `FINDING` — a vulnerability has been confirmed; writes a report file.
     - `DONE` — exploration is complete.
6. **Teardown** — Terminates the MCP server and prints a summary.

## Findings

Finding reports are written as markdown files to the `--findings-dir` directory:

```
findings/
├── finding-01-reflected-xss-in-search.md
├── finding-02-idor-in-user-api.md
└── ...
```

Each file contains the structured report produced by the orchestrator, including
title, severity, affected endpoints, reproduction steps, evidence, and impact.

## Safety Bounds

- **Max iterations**: Configurable hard cap (default 30).
- **Cost ceiling**: Optional `--max-cost` flag halts the loop if total USD cost
  is exceeded.
- **Stall detection**: Three consecutive `CONTINUE` decisions without an
  `EXPAND` or `FINDING` triggers a warning to the orchestrator, forcing it to
  either change approach or terminate.
- **Worker timeout**: If the worker produces no response within 5 minutes, it is
  interrupted and the orchestrator is consulted.
