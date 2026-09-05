#!/usr/bin/env python3
"""
Phish-Tracker // Threat Intel & Typosquatting Watcher
A production-grade tool for detecting typosquatted domains and phishing infrastructure.
"""

import asyncio
import json
import sys
from dataclasses import dataclass, field
from typing import List, Optional, Set

import dns.asyncresolver
import dns.resolver
from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich import box
from rich.align import Align
from rich.text import Text
from rich.layout import Layout

# ----------------------------------------------------------------------
# Configuration and constants
# ----------------------------------------------------------------------
MAX_VARIANTS = 1000  # Hard limit to prevent API abuse and performance degradation
CONCURRENT_DNS_QUERIES = 100
DNS_TIMEOUT = 3.0  # seconds

# Homoglyph mapping (character substitutions)
HOMOGLYPHS = {
    'a': ['4', '@'],
    'b': ['8', '6'],
    'c': ['('],
    'e': ['3'],
    'g': ['9', '6'],
    'i': ['1', '!', 'l'],
    'l': ['1', 'i'],
    'o': ['0'],
    's': ['5', '$'],
    't': ['7', '+'],
    'z': ['2'],
}

# Common phishing keywords to append/prepend
PHISHING_KEYWORDS = ['login', 'verify', 'portal', 'update', 'secure', 'account']

# ----------------------------------------------------------------------
# Data classes
# ----------------------------------------------------------------------
@dataclass
class DomainVariant:
    domain: str
    status: str = "pending"  # pending, checking, available, registered, critical, high
    ip: Optional[str] = None
    mx_servers: List[str] = field(default_factory=list)
    risk_level: str = "UNKNOWN"
    error: Optional[str] = None

    def __str__(self):
        return self.domain


# ----------------------------------------------------------------------
# Typosquatting Engine
# ----------------------------------------------------------------------
class TyposquatEngine:
    """Generates domain variations based on common typosquatting techniques."""

    def __init__(self, target_domain: str, max_variants: int = MAX_VARIANTS):
        self.target_domain = target_domain.lower()
        self.max_variants = max_variants
        # Split into base and TLD (assume last dot separates)
        parts = self.target_domain.split('.')
        if len(parts) < 2:
            raise ValueError("Invalid domain: must contain at least one dot")
        self.base = '.'.join(parts[:-1])
        self.tld = parts[-1]
        self.variants: Set[str] = set()

    def generate(self) -> List[DomainVariant]:
        """Generate all variations, deduplicate, and cap at max_variants."""
        self._generate_omissions()
        self._generate_insertions()
        self._generate_transpositions()
        self._generate_homoglyphs()
        self._generate_keyword_suffixes()

        # Limit
        variants_list = list(self.variants)
        if len(variants_list) > self.max_variants:
            variants_list = variants_list[:self.max_variants]

        # Convert to DomainVariant objects
        return [DomainVariant(domain=v) for v in sorted(variants_list)]

    def _add_variant(self, base: str):
        """Add a variant if valid and not the original."""
        if not base or base == self.base:
            return
        domain = f"{base}.{self.tld}"
        if domain != self.target_domain:
            self.variants.add(domain)

    def _generate_omissions(self):
        """Delete each character once."""
        base = self.base
        for i in range(len(base)):
            new_base = base[:i] + base[i+1:]
            self._add_variant(new_base)

    def _generate_insertions(self):
        """Insert common characters near each position."""
        base = self.base
        common_chars = 'abcdefghijklmnopqrstuvwxyz0123456789-_'
        for i in range(len(base) + 1):
            for ch in common_chars:
                new_base = base[:i] + ch + base[i:]
                self._add_variant(new_base)

    def _generate_transpositions(self):
        """Swap adjacent characters."""
        base = self.base
        for i in range(len(base) - 1):
            new_base = base[:i] + base[i+1] + base[i] + base[i+2:]
            self._add_variant(new_base)

    def _generate_homoglyphs(self):
        """Replace characters with visually similar ones."""
        base = self.base
        for i, char in enumerate(base):
            if char in HOMOGLYPHS:
                for replacement in HOMOGLYPHS[char]:
                    new_base = base[:i] + replacement + base[i+1:]
                    self._add_variant(new_base)

    def _generate_keyword_suffixes(self):
        """Append and prepend common phishing keywords."""
        base = self.base
        for keyword in PHISHING_KEYWORDS:
            # suffix: base-keyword
            self._add_variant(f"{base}-{keyword}")
            # prefix: keyword-base
            self._add_variant(f"{keyword}-{base}")


# ----------------------------------------------------------------------
# DNS Checker (Asynchronous)
# ----------------------------------------------------------------------
class DNSChecker:
    """Performs asynchronous DNS lookups for A and MX records."""

    def __init__(self, concurrency: int = CONCURRENT_DNS_QUERIES, timeout: float = DNS_TIMEOUT):
        self.semaphore = asyncio.Semaphore(concurrency)
        self.timeout = timeout
        self.resolver = dns.asyncresolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout

    async def check_domain(self, variant: DomainVariant) -> None:
        """Update the DomainVariant with DNS results."""
        async with self.semaphore:
            variant.status = "checking"
            try:
                # Check A record
                has_a = False
                ips = []
                try:
                    answers_a = await self.resolver.resolve(variant.domain, 'A')
                    ips = [str(rdata) for rdata in answers_a]
                    has_a = True
                except dns.resolver.NXDOMAIN:
                    # Domain does not exist
                    variant.status = "available"
                    variant.risk_level = "DISPONIBLE"
                    return
                except dns.resolver.NoAnswer:
                    pass  # No A record, but domain may exist
                except dns.resolver.NoNameservers:
                    variant.status = "available"
                    variant.risk_level = "DISPONIBLE"
                    return
                except Exception:
                    # Other DNS errors: treat as unavailable for our purposes
                    variant.status = "available"
                    variant.risk_level = "DISPONIBLE"
                    return

                # Check MX record
                has_mx = False
                mx_servers = []
                try:
                    answers_mx = await self.resolver.resolve(variant.domain, 'MX')
                    mx_servers = [str(rdata.exchange) for rdata in answers_mx]
                    has_mx = True
                except dns.resolver.NoAnswer:
                    pass
                except dns.resolver.NoNameservers:
                    pass
                except Exception:
                    pass

                # Determine risk
                if has_a and has_mx:
                    variant.status = "critical"
                    variant.risk_level = "CRÍTICO"
                    variant.ip = ips[0] if ips else None
                    variant.mx_servers = mx_servers
                elif has_a:
                    variant.status = "high"
                    variant.risk_level = "ALTO"
                    variant.ip = ips[0] if ips else None
                elif has_mx:
                    # Domain exists with MX but no A: still considered high risk
                    variant.status = "high"
                    variant.risk_level = "ALTO"
                    variant.mx_servers = mx_servers
                else:
                    # Domain exists but no A/MX? Rare, treat as available.
                    variant.status = "available"
                    variant.risk_level = "DISPONIBLE"

            except Exception as e:
                variant.status = "error"
                variant.error = str(e)
                variant.risk_level = "ERROR"


# ----------------------------------------------------------------------
# Rich TUI Console
# ----------------------------------------------------------------------
class TUIConsole:
    """Handles Rich rendering and live updates."""

    def __init__(self):
        self.console = Console()
        self.results: List[DomainVariant] = []
        self.live: Optional[Live] = None
        self.display_task: Optional[asyncio.Task] = None

    def start_live(self):
        """Initialize the Live context with an initial empty table."""
        self.live = Live(self._generate_table(), console=self.console, refresh_per_second=10)
        self.live.start()

    def stop_live(self):
        """Stop the Live context."""
        if self.live:
            self.live.stop()

    def update_results(self, results: List[DomainVariant]):
        """Update the internal results list."""
        self.results = results

    def _generate_table(self) -> Table:
        """Create a Rich Table showing all variants and their status."""
        table = Table(title="Análisis de Variaciones de Dominio", box=box.SIMPLE_HEAVY,
                      header_style="bold cyan", show_lines=False)
        table.add_column("Dominio", style="white", no_wrap=True)
        table.add_column("Estado", justify="center", style="bold")
        table.add_column("IP", style="magenta")
        table.add_column("Servidores MX", style="blue")
        table.add_column("Riesgo", justify="center", style="bold")

        for variant in self.results:
            # Determine style based on status/risk
            style = "white"
            if variant.status == "critical":
                style = "bold red"
            elif variant.status == "high":
                style = "bold yellow"
            elif variant.status == "available":
                style = "green"
            elif variant.status == "error":
                style = "red"
            elif variant.status == "checking":
                style = "cyan"
            # pending -> default

            ip_str = variant.ip if variant.ip else "—"
            mx_str = ", ".join(variant.mx_servers) if variant.mx_servers else "—"
            risk_str = variant.risk_level if variant.risk_level != "UNKNOWN" else "—"

            table.add_row(
                variant.domain,
                variant.status.upper(),
                ip_str,
                mx_str,
                risk_str,
                style=style
            )

        return table

    async def display_loop(self, update_interval: float = 0.2):
        """Periodically update the Live table."""
        while True:
            if self.live:
                self.live.update(self._generate_table())
            await asyncio.sleep(update_interval)


# ----------------------------------------------------------------------
# Main orchestrator
# ----------------------------------------------------------------------
class PhishTracker:
    """Main application class."""

    def __init__(self, target_domain: str, max_variants: int = MAX_VARIANTS):
        self.target_domain = target_domain
        self.engine = TyposquatEngine(target_domain, max_variants)
        self.checker = DNSChecker()
        self.tui = TUIConsole()
        self.results: List[DomainVariant] = []
        self.shutdown_event = asyncio.Event()

    async def run(self):
        """Execute the full workflow."""
        # Print banner
        self._print_banner()

        # Generate variations
        self.tui.console.print("[bold cyan]Generando variaciones...[/]")
        self.results = self.engine.generate()
        if not self.results:
            self.tui.console.print("[bold red]No se generaron variaciones.[/]")
            return

        self.tui.console.print(f"[green]Se generaron {len(self.results)} variaciones.[/]\n")

        # Start Live display
        self.tui.update_results(self.results)
        self.tui.start_live()
        # Start the display loop as a background task
        self.tui.display_task = asyncio.create_task(self.tui.display_loop())

        # Run DNS checks concurrently
        tasks = [asyncio.create_task(self.checker.check_domain(variant)) for variant in self.results]
        # Wait for all tasks to complete, but allow interruption
        try:
            await asyncio.gather(*tasks, return_exceptions=True)
        except KeyboardInterrupt:
            self.tui.console.print("\n[bold yellow]Interrupción recibida. Cancelando consultas...[/]")
            for t in tasks:
                t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
        finally:
            # Stop display loop and Live
            if self.tui.display_task:
                self.tui.display_task.cancel()
                try:
                    await self.tui.display_task
                except asyncio.CancelledError:
                    pass
            self.tui.stop_live()

        # Show final table
        self.tui.console.print(self.tui._generate_table())

        # Generate and export report
        self._export_report()

    def _print_banner(self):
        """Display ASCII art and title."""
        ascii_art = r"""
        ____  _     _      _     _____               _             
       |  _ \| |   (_)    | |   |_   _|             | |            
       | |_) | |__  _ ___ | |__   | |_ __ __ _  ___| | _____ _ __ 
       |  __/| '_ \| / __|| '_ \  | | '__/ _` |/ __| |/ / _ \ '__|
       | |   | | | | \__ \| | | | | | | | (_| | (__|   <  __/ |   
       |_|   |_| |_|_|___/|_| |_| |_|_|  \__,_|\___|_|\_\___|_|   
        """
        self.tui.console.print(ascii_art, style="bold red")
        self.tui.console.print(Panel.fit(
            "[bold cyan]PHISH-TRACKER // Threat Intel & Typosquatting Watcher[/]\n"
            f"[bold]Objetivo:[/] {self.target_domain}",
            border_style="red",
            padding=(1, 2)
        ))
        self.tui.console.print()

    def _export_report(self):
        """Generate JSON report and save to file."""
        summary = {
            "target_domain": self.target_domain,
            "total_variants": len(self.results),
            "registered": sum(1 for r in self.results if r.status in ("high", "critical")),
            "critical": sum(1 for r in self.results if r.status == "critical"),
            "available": sum(1 for r in self.results if r.status == "available"),
            "errors": sum(1 for r in self.results if r.status == "error"),
        }

        report = {
            "summary": summary,
            "results": [
                {
                    "domain": r.domain,
                    "status": r.status,
                    "ip": r.ip,
                    "mx_servers": r.mx_servers,
                    "risk_level": r.risk_level,
                    "error": r.error
                }
                for r in self.results
            ]
        }

        filename = "phish_report.json"
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        self.tui.console.print(f"\n[bold green]Reporte exportado a {filename}[/]")
        # Print summary
        self.tui.console.print(Panel(
            f"[bold]Resumen:[/]\n"
            f"Total analizadas: {summary['total_variants']}\n"
            f"Registradas (ALTO+CRÍTICO): {summary['registered']}\n"
            f"En riesgo CRÍTICO: {summary['critical']}\n"
            f"Disponibles: {summary['available']}\n"
            f"Errores: {summary['errors']}",
            title="Informe Final",
            border_style="cyan"
        ))


# ----------------------------------------------------------------------
# Entry point
# ----------------------------------------------------------------------
async def main():
    if len(sys.argv) < 2:
        print("Uso: python main.py <dominio-objetivo> [max_variantes]")
        sys.exit(1)

    target = sys.argv[1].strip().lower()
    # Basic validation
    if '.' not in target:
        print("Error: el dominio debe incluir TLD (ej. example.com)")
        sys.exit(1)

    max_variants = MAX_VARIANTS
    if len(sys.argv) >= 3:
        try:
            max_variants = int(sys.argv[2])
        except ValueError:
            print("El número máximo de variantes debe ser un entero.")
            sys.exit(1)

    tracker = PhishTracker(target, max_variants)
    try:
        await tracker.run()
    except KeyboardInterrupt:
        # Clean exit on Ctrl+C
        print("\n[!] Interrupción del usuario. Saliendo...")
        sys.exit(0)


if __name__ == "__main__":
    # Usar asyncio.run para manejar correctamente el event loop en Python 3.12+
    asyncio.run(main())