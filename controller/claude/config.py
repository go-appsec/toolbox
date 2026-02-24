"""Defaults and CLI argument parsing for the controller."""

import argparse
from dataclasses import dataclass

MODEL_MAP = {
    "sonnet": "claude-sonnet-4-5-20250929",
    "opus": "claude-opus-4-6",
    "haiku": "claude-haiku-4-5-20251001",
}


@dataclass
class Config:
    prompt: str
    proxy_port: int = 8181
    mcp_port: int = 9119
    findings_dir: str = "./findings"
    max_iterations: int = 30
    max_cost: float | None = None
    model: str = "sonnet"
    worker_model: str | None = None
    verbose: bool = False
    skip_build: bool = False
    workflow: str = "explore"
    external: bool = False
    api_base_url: str | None = None

    @property
    def orchestrator_model_id(self) -> str:
        return MODEL_MAP.get(self.model, self.model)

    @property
    def worker_model_id(self) -> str | None:
        if self.worker_model is None:
            return None
        return MODEL_MAP.get(self.worker_model, self.worker_model)


def parse_args() -> Config:
    parser = argparse.ArgumentParser(
        description="Autonomous security exploration controller using Claude Agent SDK",
    )
    parser.add_argument(
        "--prompt", required=True, help="Initial task prompt for the worker",
    )
    parser.add_argument(
        "--proxy-port", type=int, default=8181,
        help="Port for sectool's native proxy (default: 8181)",
    )
    parser.add_argument(
        "--mcp-port", type=int, default=9119,
        help="Port for sectool's MCP server (default: 9119)",
    )
    parser.add_argument(
        "--findings-dir", default="./findings",
        help="Directory for finding report files (default: ./findings)",
    )
    parser.add_argument(
        "--max-iterations", type=int, default=30,
        help="Hard cap on orchestrator loop iterations (default: 30)",
    )
    parser.add_argument(
        "--max-cost", type=float, default=None,
        help="USD cost ceiling; halts loop if exceeded",
    )
    parser.add_argument(
        "--model", default="sonnet",
        help="Model alias for the orchestrator: sonnet, opus, haiku (default: sonnet)",
    )
    parser.add_argument(
        "--worker-model", default=None,
        help="Override model for the Claude Code worker",
    )
    parser.add_argument(
        "--verbose", action="store_true",
        help="Print full worker and orchestrator outputs",
    )
    parser.add_argument(
        "--skip-build", action="store_true",
        help="Skip make build (use existing binary)",
    )
    parser.add_argument(
        "--workflow", default="explore",
        help="Sectool workflow mode (default: explore)",
    )
    parser.add_argument(
        "--external", action="store_true",
        help="Connect to an already-running MCP server; skips build, server start, and server teardown. Use --mcp-port and --proxy-port to specify connection details.",
    )
    parser.add_argument(
        "--api-base-url", default=None,
        help="Base URL for the Anthropic API proxy",
    )

    args = parser.parse_args()
    return Config(
        prompt=args.prompt,
        proxy_port=args.proxy_port,
        mcp_port=args.mcp_port,
        findings_dir=args.findings_dir,
        max_iterations=args.max_iterations,
        max_cost=args.max_cost,
        model=args.model,
        worker_model=args.worker_model,
        verbose=args.verbose,
        skip_build=args.skip_build,
        workflow=args.workflow,
        external=args.external,
        api_base_url=args.api_base_url,
    )
