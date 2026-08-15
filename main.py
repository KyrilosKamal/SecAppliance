"""
SecAppliance Command Line Interface.
"""
import asyncio
import sys
import os
import getpass
import logging
from pathlib import Path
from typing import Optional, List

import typer
from rich.console import Console
from rich.table import Table

from core.database import DatabaseManager
from core.network_scanner import NetworkScanner
from core.web_scanner import WebScanner
from core.report_generator import HTMLReportGenerator
from utils.logger import logger

app = typer.Typer(name="secappliance", help="SecAppliance - Network Security Scanner")
# Configure Console for PyInstaller compatibility: when frozen (no console), use safe settings
if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
    # Running in PyInstaller bundle
    console = Console(force_terminal=False, no_color=True)
else:
    # Running in normal Python environment
    console = Console()


def get_db_path() -> Path:
    """Get or create the database file path."""
    data_dir = Path("data")
    data_dir.mkdir(exist_ok=True)
    return data_dir / "secappliance.db"


def parse_ports(port_string: str) -> List[int]:
    """Parse port string like '1-65535' or '80,443,8080' into list of ports."""
    ports_list = []
    for part in port_string.split(","):
        part = part.strip()
        if "-" in part:
            # Range format: start-end
            try:
                start, end = map(int, part.split("-"))
                if not (1 <= start <= end <= 65535):
                    raise ValueError("port range must be between 1 and 65535")
                ports_list.extend(range(start, end + 1))
            except ValueError:
                console.print(f"[red]Error: Invalid port range '{part}'. Use format like '1-1024'.[/red]")
                raise typer.Exit(code=1)
        else:
            # Single port
            try:
                port = int(part)
                if not (1 <= port <= 65535):
                    raise ValueError("port must be between 1 and 65535")
                ports_list.append(port)
            except ValueError:
                console.print(f"[red]Error: Invalid port '{part}'. Please provide an integer between 1 and 65535.[/red]")
                raise typer.Exit(code=1)
    return ports_list


@app.command()
def scan(
    target: str = typer.Option(
        ..., "--target", "-t", help="Target IP address or CIDR range (e.g., '192.168.1.0/24' or '10.0.0.1')"
    ),
    output_dir: Path = typer.Option(
        Path("reports"), "--output-dir", "-o", help="Output directory path for saving generated reports."
    ),
    web_ports: str = typer.Option(
        "80,443,8080,8443", "--web-ports", "-w", help="Comma-separated list of web ports to scan"
    ),
    ports: str = typer.Option(
        "1-1024", "--ports", "-p", help="Port range to scan (e.g., '1-65535', '1-1024', or '80,443,8080')"
    ),
    username: Optional[str] = typer.Option(
        None, "--username", "-u", help="Remote SSH/WinRM username"
    ),
    password: Optional[str] = typer.Option(
        None, "--password", "-P", help="Remote password (insecure: visible in process list). Prefer the SECAPPLIANCE_PASSWORD environment variable."
    ),
    auth_type: str = typer.Option(
        "winrm", "--auth-type", "-a", help="Authentication protocol to use for deep collection ('winrm' or 'ssh')"
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v", help="Enable detailed debug logging"
    ),
    accept_unknown_hosts: bool = typer.Option(
        False, "--accept-unknown-hosts", help="Automatically accept unknown SSH host keys (insecure)."
    ),
    accept_invalid_certs: bool = typer.Option(
        False, "--accept-invalid-certs", help="Skip TLS certificate validation for WinRM and web checks (insecure)."
    ),
):
    """
    Scan a target network for vulnerabilities.
    """
    # Configure logging
    log_level = logging.DEBUG if verbose else logging.INFO
    logger.setLevel(log_level)
    for handler in logger.handlers:
        handler.setLevel(log_level)

    # Parse web ports
    try:
        web_ports_list = parse_ports(web_ports)
    except typer.Exit:
        console.print("[red]Error: Invalid web port list. Please provide comma-separated integers.[/red]")
        raise

    # Parse port ranges
    try:
        ports_list = parse_ports(ports)
        if not ports_list:
            console.print("[red]Error: No ports specified for scanning.[/red]")
            raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[red]Error parsing ports: {e}[/red]")
        raise typer.Exit(code=1)

    # Resolve credentials securely: prefer the environment variable, fall back to
    # an interactive prompt. Avoids exposing passwords on the command line.
    credentials = None
    if username:
        resolved_password = password or os.environ.get("SECAPPLIANCE_PASSWORD")
        if not resolved_password:
            try:
                resolved_password = getpass.getpass(f"Password for {username}@{target}: ")
            except (EOFError, KeyboardInterrupt):
                console.print("[red]Error: No password provided. Set SECAPPLIANCE_PASSWORD or provide a password.[/red]")
                raise typer.Exit(code=1)
        if not resolved_password:
            console.print("[red]Error: No password provided. Set SECAPPLIANCE_PASSWORD or provide a password.[/red]")
            raise typer.Exit(code=1)
        credentials = {
            "username": username,
            "password": resolved_password,
            "auth_type": auth_type
        }

    # Ensure output directory exists
    output_dir.mkdir(parents=True, exist_ok=True)

    # Run the scan
    async def run_scan():
        db_path = get_db_path()
        db = DatabaseManager(str(db_path))
        await db.connect()
        await db.initialize_tables()

        try:
            # Create scan record
            scan_id = await db.create_scan(target)
            console.print(f"[green]Scan started with ID: {scan_id}[/green]")

            # Network scan and connection collection
            console.print("[cyan]Starting network scan and connection collection...[/cyan]")
            network_scanner = NetworkScanner(
                db,
                max_concurrent=200,
                timeout=3.0,
                verbose=verbose,
                accept_unknown_hosts=accept_unknown_hosts,
                accept_invalid_certs=accept_invalid_certs,
            )
            await network_scanner.scan_targets([target], scan_id, ports_list, credentials)

            # Web scan
            console.print("[cyan]Starting web scan...[/cyan]")
            async with WebScanner(db, accept_invalid_certs=accept_invalid_certs) as web_scanner:
                await web_scanner.scan_targets([target], ports=web_ports_list, scan_id=scan_id)

            # Mark the scan complete before generating the report so the recorded
            # duration reflects the actual scan time.
            await db.update_scan_status(scan_id, "completed")

            # Generate report
            console.print("[cyan]Generating report...[/cyan]")
            report_generator = HTMLReportGenerator(db, reports_dir=str(output_dir))
            report_path = await report_generator.generate_report(scan_id)
            console.print(f"[green]Report generated: {report_path}[/green]")

        except Exception as e:
            logger.exception("Scan failed")
            await db.update_scan_status(scan_id, "failed")
            console.print(f"[red]Error: {e}[/red]")
            raise
        finally:
            await db.close()

    # Run the async function
    try:
        asyncio.run(run_scan())
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan cancelled by user.[/yellow]")
        sys.exit(0)


if __name__ == "__main__":
    app()
