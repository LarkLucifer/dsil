"""
DSIL command-line interface.
"""

from __future__ import annotations

import asyncio
import logging
from collections import Counter
from typing import Optional

import click
from dotenv import load_dotenv

from .core.ai import AgentInterface, OpenAIAgent
from .core.context import ScanContext, ScanMode
from .core.pipeline import run_pipeline

# Initialize environment variables
load_dotenv()

logger = logging.getLogger("dsil.cli")


def _setup_logging(verbosity: int) -> None:
    if verbosity <= 0:
        level = logging.WARNING
    elif verbosity == 1:
        level = logging.INFO
    else:
        level = logging.DEBUG

    logging.basicConfig(
        level=level,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )


def _build_agent(enable_ai: bool) -> Optional[AgentInterface]:
    if not enable_ai:
        return None
    try:
        return OpenAIAgent.from_env()
    except Exception as exc:  # noqa: BLE001
        logger.warning("AI agent not initialized: %s", exc)
        return None


def _print_summary(findings: list, report_paths: tuple[str, str, str] | None) -> None:
    print("")
    print("Findings Summary")
    print("================")

    if not findings:
        print("No findings.")
    else:
        counts = Counter(getattr(f, "severity", "unknown") for f in findings)
        print(f"{'Severity':<12} {'Count':>5}")
        print(f"{'-'*12} {'-'*5}")
        for severity in ["critical", "high", "medium", "low", "info", "unknown"]:
            if severity in counts:
                print(f"{severity:<12} {counts[severity]:>5}")

    if report_paths:
        print("")
        print("Reports")
        print("=======")
        print(f"JSON: {report_paths[0]}")
        print(f"MD:   {report_paths[1]}")
        print(f"HTML: {report_paths[2]}")


def _run_mode(mode: ScanMode, target: str, verbosity: int, enable_ai: bool, profile: str, max_pages: Optional[int], concurrency: Optional[int]) -> None:
    agent = _build_agent(enable_ai)
    context = ScanContext(
        target=target, 
        mode=mode, 
        profile=profile,  # type: ignore
        verbosity=verbosity, 
        agent=agent,
        max_pages=max_pages,
        concurrency=concurrency
    )
    pipeline = asyncio.run(run_pipeline(context))
    _print_summary(pipeline.findings, pipeline.report_paths)


@click.group(help="DSIL - Defensive Security Intelligence Lab")
@click.option("--target", required=True, help="Target URL or scope root.")
@click.option("-v", "--verbose", count=True, help="Increase verbosity.")
@click.option("--enable-ai/--no-enable-ai", default=False, help="Enable AI agent hooks.")
@click.option("-p", "--profile", type=click.Choice(["local", "vps"]), default="local", help="Execution profile (local=safe, vps=brutal).")
@click.option("--max-pages", type=int, help="Max unique pages to crawl during discovery. (Default based on profile)")
@click.option("--concurrency", type=int, help="Max parallel scanner tasks. (Default based on profile)")
@click.pass_context
def cli(ctx: click.Context, target: str, verbose: int, enable_ai: bool, profile: str, max_pages: Optional[int], concurrency: Optional[int]) -> None:
    _setup_logging(verbose)
    ctx.obj = {
        "target": target,
        "verbose": verbose,
        "enable_ai": enable_ai,
        "profile": profile,
        "max_pages": max_pages,
        "concurrency": concurrency,
    }


@cli.command(help="Run quick proof-of-concept checks.")
@click.pass_context
def poc(ctx: click.Context) -> None:
    opts = ctx.obj
    _run_mode("poc", opts["target"], opts["verbose"], opts["enable_ai"], opts["profile"], opts["max_pages"], opts["concurrency"])


@cli.command(help="Run deep crawling and scanning.")
@click.pass_context
def scan(ctx: click.Context) -> None:
    opts = ctx.obj
    _run_mode("scan", opts["target"], opts["verbose"], opts["enable_ai"], opts["profile"], opts["max_pages"], opts["concurrency"])


@cli.command(help="Run static analysis pipeline.")
@click.pass_context
def sast(ctx: click.Context) -> None:
    opts = ctx.obj
    _run_mode("sast", opts["target"], opts["verbose"], opts["enable_ai"], opts["profile"], opts["max_pages"], opts["concurrency"])


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
