"""VeriSol CLI interface."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from verisol import __version__
from verisol.core.contract import Contract
from verisol.core.report import AuditReport, Severity
from verisol.pipeline import VerificationPipeline

app = typer.Typer(
    name="verisol",
    help="AI-powered smart contract security verification",
    add_completion=False,
)
# Console for stdout (normal output)
console = Console()
# Console for stderr (warnings, errors - used in JSON mode)
stderr_console = Console(stderr=True)


def version_callback(value: bool) -> None:
    if value:
        console.print(f"VeriSol v{__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Optional[bool] = typer.Option(
        None,
        "--version",
        "-v",
        help="Show version and exit",
        callback=version_callback,
        is_eager=True,
    ),
) -> None:
    """VeriSol - Smart Contract Security Verification"""
    pass


@app.command()
def audit(
    contract_path: Optional[Path] = typer.Argument(
        None,
        help="Path to Solidity contract file",
    ),
    address: Optional[str] = typer.Option(
        None,
        "--address",
        "-a",
        help="Contract address to fetch from Etherscan (e.g. 0x1234...)",
    ),
    chain: str = typer.Option(
        "ethereum",
        "--chain",
        "-c",
        help="Chain for address lookup (ethereum, polygon, arbitrum, optimism, base)",
    ),
    fork_url: Optional[str] = typer.Option(
        None,
        "--fork-url",
        help="RPC URL for fork mode (exploit tests run against on-chain state)",
    ),
    block: Optional[int] = typer.Option(
        None,
        "--block",
        "-b",
        help="Pin fork to a specific block number",
    ),
    quick: bool = typer.Option(
        False,
        "--quick",
        "-q",
        help="Quick mode: Slither only (fastest)",
    ),
    offline: bool = typer.Option(
        False,
        "--offline",
        help="Offline mode: Slither + SMTChecker, no LLM (free, no API)",
    ),
    full: bool = typer.Option(
        False,
        "--full",
        "-f",
        help="Full mode: Slither + LLM + SMTChecker (slow but complete)",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Save report to file (markdown)",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        "-j",
        help="Output as JSON instead of formatted (clean output for CI)",
    ),
    exploit: bool = typer.Option(
        False,
        "--exploit",
        "-x",
        help="Generate and run exploit tests to prove exploitability",
    ),
) -> None:
    """
    Audit a smart contract for security vulnerabilities.

    Sources (exactly one required):
      CONTRACT_PATH: Local Solidity file
      --address/-a:  Fetch verified source from Etherscan

    Modes:
      Default:   Slither + LLM (fast, thorough)
      --quick:   Slither only (fastest, free)
      --offline: Slither + SMTChecker (free, no API needed)
      --full:    Slither + LLM + SMTChecker (slow but complete)

    Fork Mode:
      --address + --exploit: Run exploits against real on-chain state
      --fork-url:            Override RPC URL (default from .env)
      --block/-b:            Pin to a specific block number

    Exploit Simulation:
      --exploit: Generate and run Foundry exploit tests to prove exploitability
    """
    from verisol.config import get_settings

    # In JSON mode, all non-JSON output goes to stderr
    out = stderr_console if json_output else console

    # Validate: exactly one of contract_path or address
    if contract_path and address:
        out.print("[red]Error:[/red] Provide either a contract path or --address, not both")
        raise typer.Exit(1)
    if not contract_path and not address:
        out.print("[red]Error:[/red] Provide a contract path or --address")
        raise typer.Exit(1)

    settings = get_settings()
    resolved_fork_url: str | None = None

    if address:
        # --- Address path: fetch from Etherscan ---
        if not json_output:
            out.print(f"\n[bold]Fetching contract:[/bold] {address} on {chain}")

        try:
            contract = asyncio.run(
                Contract.from_address(
                    address,
                    chain=chain,
                    api_key=settings.etherscan_api_key,
                )
            )
        except Exception as e:
            if json_output:
                error_json = {
                    "error": True,
                    "message": f"Error fetching contract: {e}",
                    "address": address,
                    "chain": chain,
                }
                print(json.dumps(error_json, indent=2))
            else:
                out.print(f"[red]Error fetching contract:[/red] {e}")
            raise typer.Exit(1)

        # Resolve fork URL for exploit mode
        if exploit:
            resolved_fork_url = fork_url or settings.get_rpc_url(chain)
            if not resolved_fork_url and not json_output:
                out.print(
                    "[yellow]Warning:[/yellow] No RPC URL for fork mode. "
                    "Exploits will run without on-chain state. "
                    f"Set {chain.upper()}_RPC_URL or use --fork-url."
                )
    else:
        # --- File path ---
        assert contract_path is not None
        if not contract_path.exists():
            out.print(f"[red]Error:[/red] Contract file not found: {contract_path}")
            raise typer.Exit(1)

        try:
            contract = Contract.from_file(contract_path)
        except Exception as e:
            if json_output:
                error_json = {
                    "error": True,
                    "message": f"Error loading contract: {e}",
                    "contract_path": str(contract_path),
                }
                print(json.dumps(error_json, indent=2))
            else:
                out.print(f"[red]Error loading contract:[/red] {e}")
            raise typer.Exit(1)

        # Allow --fork-url even for local files
        resolved_fork_url = fork_url

    # Print header (to stderr in JSON mode)
    if not json_output:
        display_name = contract.name or (contract_path.name if contract_path else address)
        out.print(f"\n[bold]Auditing:[/bold] {display_name}")
        if address:
            out.print(f"[dim]Address: {address} ({chain})[/dim]")
        out.print(f"[dim]Lines of code: {contract.lines_of_code}[/dim]")
        out.print(f"[dim]Solidity version: {contract.solidity_version or 'unknown'}[/dim]")
        if resolved_fork_url:
            out.print(f"[dim]Fork mode: {resolved_fork_url}[/dim]")
        out.print()

    # Run verification (quiet mode for JSON)
    report = asyncio.run(_run_audit(contract, quick=quick, offline=offline, full=full, quiet=json_output))

    # Run exploit simulation if requested
    if exploit and report.all_findings:
        asyncio.run(_run_exploit_simulation(
            report, contract,
            quiet=json_output, console_out=out,
            fork_url=resolved_fork_url, fork_block=block,
        ))

    # Output results
    if json_output:
        # Clean JSON to stdout
        print(json.dumps(report.to_json(), indent=2))
    else:
        _print_report(report)

    # Save to file if requested
    if output:
        output.write_text(report.to_markdown())
        out.print(f"\n[dim]Report saved to {output}[/dim]")

    # Exit with appropriate code
    if not report.passed:
        raise typer.Exit(1)


async def _run_audit(contract: Contract, quick: bool = False, offline: bool = False, full: bool = False, quiet: bool = False) -> AuditReport:
    """Run the audit with optional progress display.

    Args:
        contract: Contract to audit
        quick: Run quick verification only (slither only)
        offline: Run offline mode (slither + smtchecker, no LLM)
        full: Run full verification including SMTChecker (slow)
        quiet: Suppress progress output (for JSON mode)
    """
    pipeline = VerificationPipeline()

    # Check tools first
    tools = pipeline.check_tools()
    missing = [name for name, available in tools.items() if not available]

    if missing and not quiet:
        console.print(f"[yellow]Warning:[/yellow] Some tools not available: {', '.join(missing)}")
        console.print("[dim]Install missing tools for complete verification[/dim]\n")

    if quiet:
        # Silent mode - no progress display
        if quick:
            report = await pipeline.run_quick(contract)
        else:
            report = await pipeline.run(contract, include_smt=(full or offline), skip_llm=offline)
    else:
        # Normal mode with progress spinner
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Running verification...", total=None)

            def update_progress(stage: str, status: str) -> None:
                emoji = "✓" if status == "passed" else "✗" if status == "failed" else "→"
                progress.update(task, description=f"{emoji} {stage}: {status}")

            pipeline.set_progress_callback(update_progress)

            if quick:
                report = await pipeline.run_quick(contract)
            else:
                report = await pipeline.run(contract, include_smt=(full or offline), skip_llm=offline)

    return report


async def _run_exploit_simulation(
    report: AuditReport,
    contract: Contract,
    quiet: bool = False,
    console_out: Console | None = None,
    fork_url: str | None = None,
    fork_block: int | None = None,
) -> None:
    """Run exploit simulation for findings in the report."""
    from verisol.exploits.runner import run_exploits_for_findings, check_foundry_available

    out = console_out or console

    if not quiet:
        mode_label = " (fork mode)" if fork_url else ""
        out.print(f"\n[bold]Running Exploit Simulation{mode_label}...[/bold]")

    # Check if Foundry is available
    if not check_foundry_available():
        if not quiet:
            out.print("[yellow]Warning:[/yellow] Foundry (forge) not installed")
            out.print("[dim]Install: curl -L https://foundry.paradigm.xyz | bash && foundryup[/dim]")
        return

    # Get contract name from the contract object
    contract_name = contract.name or "Unknown"

    # Filter to HIGH+ severity findings for exploit generation
    from verisol.core.report import Severity
    exploit_findings = [
        f for f in report.all_findings
        if f.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM)
    ]

    # Run exploits for high-signal findings (async — may call LLM)
    results = await run_exploits_for_findings(
        findings=exploit_findings,
        contract_code=contract.code,
        contract_name=contract_name,
        fork_url=fork_url,
        fork_block=fork_block,
        source_files=contract.source_files,
    )

    if not quiet:
        # Print exploit results
        exploitable_count = sum(1 for _, r in results if r.exploitable)
        total_generated = sum(1 for _, r in results if r.generated)

        out.print(f"\n[bold]Exploit Results:[/bold] {exploitable_count}/{total_generated} EXPLOITABLE")

        for finding, result in results:
            if result.exploitable:
                profit_str = f"{result.profit_wei} wei" if result.profit_wei else "unknown"
                attempt_str = f", {result.attempts} attempt{'s' if result.attempts != 1 else ''}" if result.attempts > 1 else ""
                method_str = f" via {result.generation_method}" if result.generation_method != "template" else ""
                out.print(f"  [red]EXPLOITABLE[/red] {finding.title} (profit: {profit_str}{attempt_str}{method_str})")
            elif result.generated and result.executed:
                out.print(f"  [green]NOT EXPLOITABLE[/green] {finding.title} ({result.attempts} attempts)")
                if result.error:
                    out.print(f"    [dim]Error: {result.error[:200]}[/dim]")
            elif result.generated:
                out.print(f"  [yellow]NOT EXECUTED[/yellow] {finding.title}: {result.error or 'unknown error'}")
            else:
                out.print(f"  [dim]NO EXPLOIT[/dim] {finding.title}")


def _print_report(report: AuditReport) -> None:
    """Print formatted report to console."""
    # Summary panel
    status_color = "green" if report.passed else "red"
    status_text = "PASSED" if report.passed else "FAILED"
    
    summary = f"""
[bold]Score:[/bold] {report.overall_score:.0%}
[bold]Status:[/bold] [{status_color}]{status_text}[/{status_color}]
[bold]Confidence:[/bold] {report.confidence.upper()}
[bold]Duration:[/bold] {report.total_duration_ms}ms
    """
    
    console.print(Panel(summary.strip(), title="Audit Summary", border_style=status_color))
    
    # Findings table
    if report.all_findings:
        table = Table(title="Findings", show_header=True, header_style="bold")
        table.add_column("Severity", style="bold", width=12)
        table.add_column("Title", width=40)
        table.add_column("Detector", width=25)
        table.add_column("Location", width=15)
        
        severity_colors = {
            Severity.CRITICAL: "red bold",
            Severity.HIGH: "red",
            Severity.MEDIUM: "yellow",
            Severity.LOW: "cyan",
            Severity.INFO: "dim",
        }
        
        for finding in sorted(report.all_findings, key=lambda f: f.severity.weight, reverse=True):
            color = severity_colors.get(finding.severity, "white")
            location = f"L{finding.line_start}" if finding.line_start else "-"
            
            table.add_row(
                f"[{color}]{finding.severity.value.upper()}[/{color}]",
                finding.title[:40],
                finding.detector[:25],
                location,
            )
        
        console.print(table)
    else:
        console.print("\n[green]No security issues found![/green]")
    
    # Verification details
    console.print("\n[bold]Verification Details:[/bold]")
    
    for name, result in [
        ("Compilation", report.compilation),
        ("Slither", report.slither),
        ("SMTChecker", report.smtchecker),
        ("LLM", report.llm),
    ]:
        if result:
            status_emoji = "✓" if result.passed else "✗" if result.status.value == "failed" else "⚠"
            status_color = "green" if result.passed else "red" if result.status.value == "failed" else "yellow"
            
            details = f"[{status_color}]{status_emoji}[/{status_color}] {name}: {result.status.value}"
            
            if result.properties_checked > 0:
                details += f" ({result.properties_proven}/{result.properties_checked} properties proven)"
            
            if result.finding_counts:
                counts = [f"{k}={v}" for k, v in result.finding_counts.items() if v > 0]
                if counts:
                    details += f" [{', '.join(counts)}]"
            
            console.print(f"  {details}")


@app.command()
def check() -> None:
    """Check if verification tools are installed."""
    from verisol.config import get_settings
    from verisol.exploits.runner import check_foundry_available

    settings = get_settings()
    pipeline = VerificationPipeline()
    tools = pipeline.check_tools()

    # Add Foundry check
    tools["foundry"] = check_foundry_available()

    # Add Etherscan check
    tools["etherscan"] = bool(settings.etherscan_api_key)

    table = Table(title="Verification Tools", show_header=True)
    table.add_column("Tool", style="bold")
    table.add_column("Status")
    table.add_column("Purpose")

    tool_info = {
        "solc": "Solidity compilation",
        "slither": "Static analysis (90+ detectors)",
        "smtchecker": "Formal verification (built into solc)",
        "llm": "LLM-based security analysis (requires API key)",
        "foundry": "Exploit simulation (--exploit flag)",
        "etherscan": "Contract source fetching (--address flag)",
    }

    for name, available in tools.items():
        status = "[green]✓ Available[/green]" if available else "[red]✗ Not found[/red]"
        table.add_row(name, status, tool_info.get(name, ""))

    console.print(table)

    # RPC URLs status
    rpc_table = Table(title="Fork Mode RPC URLs", show_header=True)
    rpc_table.add_column("Chain", style="bold")
    rpc_table.add_column("Status")

    for chain_name in ["ethereum", "polygon", "arbitrum", "optimism", "base"]:
        url = settings.get_rpc_url(chain_name)
        if url:
            rpc_table.add_row(chain_name, "[green]✓ Configured[/green]")
        else:
            rpc_table.add_row(chain_name, "[dim]Not set[/dim]")

    console.print(rpc_table)

    # Installation hints
    missing = [name for name, available in tools.items() if not available]
    if missing:
        console.print("\n[bold]Installation:[/bold]")
        if "solc" in missing:
            console.print("  solc: pip install solc-select && solc-select install 0.8.24")
        if "slither" in missing:
            console.print("  slither: pip install slither-analyzer")
        if "llm" in missing:
            console.print("  llm: Set OPENAI_API_KEY or ANTHROPIC_API_KEY environment variable")
        if "foundry" in missing:
            console.print("  foundry: curl -L https://foundry.paradigm.xyz | bash && foundryup")
        if "etherscan" in missing:
            console.print("  etherscan: Set ETHERSCAN_API_KEY environment variable")


@app.command()
def report(
    contract_path: Path = typer.Argument(..., help="Path to contract"),
    output: Path = typer.Option(
        Path("audit-report.md"),
        "--output",
        "-o",
        help="Output file path",
    ),
) -> None:
    """Generate a full markdown audit report."""
    try:
        contract = Contract.from_file(contract_path)
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1)
    
    console.print(f"[bold]Generating report for:[/bold] {contract.name}")
    
    report = asyncio.run(_run_audit(contract, quick=False))
    
    output.write_text(report.to_markdown())
    console.print(f"\n[green]Report saved to:[/green] {output}")


if __name__ == "__main__":
    app()
