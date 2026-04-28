"""Typer CLI for mysql_enum."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from .config import TargetConfig
from .enumerator import MySQLEnumerator

app = typer.Typer(help="MySQL/MariaDB enumeration tool for penetration testing.")
console = Console()

_DEFAULT_OUTPUT = Path("output")


def _build_config(
    target: str,
    port: int,
    username: Optional[str],
    password: Optional[str],
    password_file: Optional[Path],
    output_dir: Path,
    sample_rows: int,
    preserve_sensitive: bool,
) -> TargetConfig:
    pw: Optional[str] = password
    if pw is None and password_file and password_file.exists():
        pw = password_file.read_text().strip()

    from pydantic import SecretStr
    return TargetConfig(
        target=target,
        port=port,
        username=username,
        password=SecretStr(pw) if pw else None,
        output_dir=output_dir,
        sample_rows=sample_rows,
        preserve_sensitive=preserve_sensitive,
    )


@app.command()
def discover(
    target: str = typer.Argument(..., help="Target IP or hostname"),
    port: int = typer.Option(3306, help="MySQL port"),
    output_dir: Path = typer.Option(_DEFAULT_OUTPUT, help="Base output directory"),
) -> None:
    """Discover and fingerprint the MySQL service (no credentials required)."""
    config = TargetConfig(target=target, port=port, output_dir=output_dir)
    enumerator = MySQLEnumerator(config)
    result = enumerator.run_discover()
    if result.reachable:
        console.print(f"[green]Service reachable at {target}:{port}[/]")
    else:
        console.print(f"[red]Service unreachable: {result.error}[/]")
        raise typer.Exit(1)


@app.command()
def metadata(
    target: str = typer.Argument(..., help="Target IP or hostname"),
    port: int = typer.Option(3306, help="MySQL port"),
    username: Optional[str] = typer.Option(None, "--username", "-u", help="MySQL username"),
    password: Optional[str] = typer.Option(None, "--password", "-p", help="MySQL password"),
    password_file: Optional[Path] = typer.Option(None, "--password-file", help="File containing password"),
    output_dir: Path = typer.Option(_DEFAULT_OUTPUT, help="Base output directory"),
    preserve_sensitive: bool = typer.Option(False, help="Preserve sensitive values in reports"),
) -> None:
    """Enumerate metadata, schema, users, and privileges."""
    config = _build_config(target, port, username, password, password_file, output_dir, 20, preserve_sensitive)
    enumerator = MySQLEnumerator(config)
    result = enumerator.run_metadata()
    if not result.authenticated:
        console.print(f"[red]Enumeration failed: {result.error}[/]")
        raise typer.Exit(1)
    console.print(f"[green]Output written to {config.target_dir}[/]")


@app.command()
def sample(
    target: str = typer.Argument(..., help="Target IP or hostname"),
    port: int = typer.Option(3306, help="MySQL port"),
    username: Optional[str] = typer.Option(None, "--username", "-u", help="MySQL username"),
    password: Optional[str] = typer.Option(None, "--password", "-p", help="MySQL password"),
    password_file: Optional[Path] = typer.Option(None, "--password-file", help="File containing password"),
    rows: int = typer.Option(20, "--rows", help="Rows per table to sample"),
    output_dir: Path = typer.Option(_DEFAULT_OUTPUT, help="Base output directory"),
    preserve_sensitive: bool = typer.Option(False, "--preserve-sensitive", help="Preserve sensitive values"),
) -> None:
    """Sample data from high-value tables."""
    config = _build_config(target, port, username, password, password_file, output_dir, rows, preserve_sensitive)
    enumerator = MySQLEnumerator(config)
    result = enumerator.run_sample()
    if not result.authenticated:
        console.print(f"[red]Enumeration failed: {result.error}[/]")
        raise typer.Exit(1)
    console.print(f"[green]Sampled {len(result.samples)} tables. Output: {config.target_dir}[/]")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
