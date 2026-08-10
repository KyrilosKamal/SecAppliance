"""
SecAppliance Command Line Interface.
"""
import asyncio
import sys
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
        None, "--password", "-P", help="Remote password"
    ),
    auth_type: str = typer.Option(
        "winrm", "--auth-type", "-a", help="Authentication protocol to use for deep collection ('winrm' or 'ssh')"
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v", help="Enable detailed debug logging"
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
        web_ports_list = [int(p.strip()) for p in web_ports.split(",") if p.strip()]
    except ValueError:
        console.print("[red]Error: Invalid web port list. Please provide comma-separated integers.[/red]")
        raise typer.Exit(code=1)

    # Parse port ranges
    def parse_ports(port_string: str) -> List[int]:
        """Parse port string like '1-65535' or '80,443,8080' into list of ports."""
        ports_list = []
        for part in port_string.split(","):
            part = part.strip()
            if "-" in part:
                # Range format: start-end
                try:
                    start, end = map(int, part.split("-"))
                    ports_list.extend(range(start, end + 1))
                except ValueError:
                    console.print(f"[red]Error: Invalid port range '{part}'. Use format like '1-1024'.[/red]")
                    raise typer.Exit(code=1)
            else:
                # Single port
                try:
                    ports_list.append(int(part))
                except ValueError:
                    console.print(f"[red]Error: Invalid port '{part}'. Please provide an integer.[/red]")
                    raise typer.Exit(code=1)
        return ports_list

    try:
        ports_list = parse_ports(ports)
        if not ports_list:
            console.print("[red]Error: No ports specified for scanning.[/red]")
            raise typer.Exit(code=1)
        # Limit to reasonable range to prevent accidents
        if any(p < 1 or p > 65535 for p in ports_list):
            console.print("[red]Error: Ports must be between 1 and 65535.[/red]")
            raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[red]Error parsing ports: {e}[/red]")
        raise typer.Exit(code=1)

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
            network_scanner = NetworkScanner(db, max_concurrent=200, timeout=3.0, verbose=verbose)
            credentials = {"username": username, "password": password, "auth_type": auth_type} if username and password else None
            await network_scanner.scan_targets([target], scan_id, ports_list, credentials)

            # Web scan
            console.print("[cyan]Starting web scan...[/cyan]")
            async with WebScanner(db) as web_scanner:
                await web_scanner.scan_targets([target], ports=web_ports_list, scan_id=scan_id)

            # Generate report
            console.print("[cyan]Generating report...[/cyan]")
            report_generator = HTMLReportGenerator(db, reports_dir=str(output_dir))
            report_path = await report_generator.generate_report(scan_id)
            console.print(f"[green]Report generated: {report_path}[/green]")

        except Exception as e:
            logger.exception("Scan failed")
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