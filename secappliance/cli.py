"""
SecAppliance Command Line Interface.
"""
import asyncio
import sys
import os
import logging
from enum import Enum
from pathlib import Path
from typing import Optional, List

import click
import typer
from rich.console import Console

from secappliance import __version__
from secappliance.core.database import DatabaseManager
from secappliance.core.network_scanner import NetworkScanner
from secappliance.core.web_scanner import WebScanner
from secappliance.core.report_generator import HTMLReportGenerator
from secappliance.utils.logger import attach_file_handler, logger

class AuthType(str, Enum):
    """Authentication protocol used for deep connection collection."""
    winrm = "winrm"
    ssh = "ssh"


app = typer.Typer(name="secappliance", help="SecAppliance - Network Security Scanner")
# Configure Console for PyInstaller compatibility: when frozen (no console), use safe settings
if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
    # Running in PyInstaller bundle
    console = Console(force_terminal=False, no_color=True)
else:
    # Running in normal Python environment
    console = Console()


def get_app_data_dir() -> Path:
    """Return the per-user data directory, creating it if needed.

    Uses platformdirs when installed (~/.local/share/SecAppliance on Linux) and
    falls back to ~/.secappliance, so state never depends on the working
    directory the command happens to be run from.
    """
    try:
        import platformdirs
        data_dir = Path(platformdirs.user_data_dir("SecAppliance"))
    except ImportError:
        data_dir = Path.home() / ".secappliance"
    data_dir.mkdir(parents=True, exist_ok=True)
    return data_dir


def get_db_path() -> Path:
    """Get or create the database file path."""
    return get_app_data_dir() / "secappliance.db"


def get_log_path() -> Path:
    """Get the log file path."""
    return get_app_data_dir() / "secappliance.log"


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


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"secappliance {__version__}")
        raise typer.Exit()


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
    auth_type: AuthType = typer.Option(
        AuthType.winrm, "--auth-type", "-a", help="Authentication protocol to use for deep collection."
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
    force: bool = typer.Option(
        False, "--force", help="Allow scanning CIDR ranges larger than /16 (hosts are streamed, not materialized)."
    ),
    offline: bool = typer.Option(
        False, "--offline", help="Skip the online CIRCL CVE lookup so no banner/version data leaves this machine."
    ),
    version: bool = typer.Option(
        False, "--version", callback=_version_callback, is_eager=True, help="Show version and exit."
    ),
    allow_insecure_winrm_http: bool = typer.Option(
        False, "--allow-insecure-winrm-http", help="Allow WinRM over plaintext HTTP on port 5985 (NTLM credentials are sent unencrypted). WinRM uses HTTPS on port 5986 by default."
    ),
):
    """
    Scan a target network for vulnerabilities.

    The password is never accepted as an argument: it is read from the
    SECAPPLIANCE_PASSWORD environment variable, or prompted for without echo when
    that variable is unset.
    """
    # Configure logging
    attach_file_handler(logger, get_log_path())
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

    # Credentials never come from the command line: a --password flag would leak
    # the secret into the process list and shell history. Read the environment
    # variable first, otherwise prompt without echo.
    credentials = None
    if username:
        resolved_password = os.environ.get("SECAPPLIANCE_PASSWORD")
        if not resolved_password:
            try:
                resolved_password = typer.prompt(f"Password for {username}@{target}", hide_input=True)
            # click.Abort (older typer) or typer.Abort (current) means EOF/Ctrl-C.
            except (EOFError, KeyboardInterrupt, click.Abort, typer.Abort):
                console.print("[red]Error: No password provided. Set SECAPPLIANCE_PASSWORD or enter one at the prompt.[/red]")
                raise typer.Exit(code=1)
        if not resolved_password:
            console.print("[red]Error: No password provided. Set SECAPPLIANCE_PASSWORD or enter one at the prompt.[/red]")
            raise typer.Exit(code=1)
        credentials = {
            "username": username,
            "password": resolved_password,
            "auth_type": auth_type.value
        }

    # Ensure output directory exists
    output_dir.mkdir(parents=True, exist_ok=True)

    # Run the scan
    async def run_scan():
        db_path = get_db_path()
        db = DatabaseManager(str(db_path))
        await db.connect()
        await db.initialize_tables()

        scan_id = None
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
                force=force,
                allow_insecure_winrm_http=allow_insecure_winrm_http,
                offline=offline,
            )
            await network_scanner.scan_targets([target], scan_id, ports_list, credentials)

            # Web scan
            console.print("[cyan]Starting web scan...[/cyan]")
            async with WebScanner(db, accept_invalid_certs=accept_invalid_certs, offline=offline) as web_scanner:
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
            if scan_id is not None:
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


def main() -> None:
    """Console-script entry point."""
    app()


if __name__ == "__main__":
    main()
