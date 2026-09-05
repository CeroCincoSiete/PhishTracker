#!/usr/bin/env python3
"""
Phish-Tracker // Threat Intel & Typosquatting Watcher
Herramienta de consola para detectar dominios typosquatted y posible
infraestructura de phishing que suplante a un dominio/marca objetivo.

Uso básico:
    python main.py ejemplo.com

Opciones útiles:
    python main.py ejemplo.com --max-variants 500 --concurrency 150
    python main.py ejemplo.com --whois          # verifica antigüedad de registro
    python main.py ejemplo.com --crtsh          # busca en Certificate Transparency
    python main.py ejemplo.com --nameservers 1.1.1.1,8.8.8.8
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import json
import signal
import sys
from dataclasses import dataclass, field
from typing import List, Optional, Set, Tuple

import dns.asyncresolver
import dns.resolver
from rich.console import Console, Group
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn, MofNCompleteColumn
from rich import box

try:
    import tldextract  # Manejo correcto de TLDs compuestos (co.uk, com.ar, etc.)
    # Forzar uso exclusivo del snapshot local incluido en el paquete: nunca debe
    # intentar descargar la lista de sufijos públicos por red (esta herramienta
    # suele correr en redes restringidas/aisladas de pentesting).
    _tldextractor = tldextract.TLDExtract(suffix_list_urls=())
    _HAS_TLDEXTRACT = True
except ImportError:
    _HAS_TLDEXTRACT = False

try:
    import whois as whois_lib  # python-whois, opcional
    _HAS_WHOIS = True
except ImportError:
    _HAS_WHOIS = False

try:
    import aiohttp  # Para consulta opcional a crt.sh
    _HAS_AIOHTTP = True
except ImportError:
    _HAS_AIOHTTP = False


# ----------------------------------------------------------------------
# Configuración y constantes
# ----------------------------------------------------------------------
MAX_VARIANTS_DEFAULT = 1000
CONCURRENT_DNS_QUERIES_DEFAULT = 100
DNS_TIMEOUT_DEFAULT = 3.0
WHOIS_CONCURRENCY = 10          # WHOIS es mucho más lento/rate-limited que DNS
RECENTLY_REGISTERED_DAYS = 30   # umbral para marcar "recién registrado" como sospechoso

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

PHISHING_KEYWORDS = ['login', 'verify', 'portal', 'update', 'secure', 'account', 'support', 'signin']

# TLDs comunes usados para "TLD swapping" en campañas reales de phishing
COMMON_TLDS = ['com', 'net', 'org', 'info', 'biz', 'co', 'io', 'me',
               'xyz', 'online', 'site', 'top', 'cc', 'shop', 'live']


# ----------------------------------------------------------------------
# Modelos de datos
# ----------------------------------------------------------------------
@dataclass
class DomainVariant:
    domain: str
    technique: str = "unknown"
    status: str = "pending"          # pending, checking, available, high, critical, error
    ip: Optional[str] = None
    mx_servers: List[str] = field(default_factory=list)
    risk_level: str = "UNKNOWN"
    error: Optional[str] = None
    created_date: Optional[str] = None
    days_since_registration: Optional[int] = None
    recently_registered: bool = False

    def __str__(self) -> str:
        return self.domain

    # Orden de severidad para ordenar tablas/reportes
    _SEVERITY = {"critical": 0, "high": 1, "error": 3, "checking": 4, "pending": 5, "available": 6}

    @property
    def severity(self) -> int:
        return self._SEVERITY.get(self.status, 9)


# ----------------------------------------------------------------------
# Motor de Typosquatting
# ----------------------------------------------------------------------
class TyposquatEngine:
    """Genera variaciones de dominio típicas de typosquatting, priorizadas
    de más a menos realistas para que el truncado por max_variants no
    descarte primero las variantes más relevantes."""

    def __init__(self, target_domain: str, max_variants: int = MAX_VARIANTS_DEFAULT):
        self.target_domain = target_domain.lower().strip()
        self.max_variants = max_variants
        self.base, self.tld = self._split_domain(self.target_domain)
        if not self.base:
            raise ValueError("Dominio inválido: no se pudo extraer la parte base")
        # Cada técnica aporta una lista ordenada de (dominio, técnica).
        # El orden entre técnicas define la prioridad de conservación al truncar.
        self._seen: Set[str] = {self.target_domain}

    def _split_domain(self, domain: str) -> Tuple[str, str]:
        """Separa base y TLD. Usa tldextract si está disponible para manejar
        TLDs compuestos (ej. empresa.co.uk); si no, cae al método simple."""
        if _HAS_TLDEXTRACT:
            ext = _tldextractor(domain)
            if ext.domain and ext.suffix:
                return ext.domain, ext.suffix
        parts = domain.split('.')
        if len(parts) < 2:
            raise ValueError("El dominio debe incluir un TLD (ej. example.com)")
        return '.'.join(parts[:-1]), parts[-1]

    def generate(self) -> List[DomainVariant]:
        """Genera variantes priorizadas y las trunca a max_variants."""
        ordered: List[Tuple[str, str]] = []
        # Prioridad alta: patrones más usados en campañas reales de phishing
        ordered += self._gen_keyword_suffixes()
        ordered += self._gen_tld_swap()
        ordered += self._gen_homoglyphs()
        ordered += self._gen_transpositions()
        ordered += self._gen_omissions()
        # Prioridad baja: combinatoria más ruidosa
        ordered += self._gen_insertions()

        # Deduplicar conservando el primer orden de aparición (= prioridad)
        deduped: List[Tuple[str, str]] = []
        seen_domains: Set[str] = set()
        for domain, technique in ordered:
            if domain in seen_domains:
                continue
            seen_domains.add(domain)
            deduped.append((domain, technique))

        if len(deduped) > self.max_variants:
            deduped = deduped[: self.max_variants]

        variants = [DomainVariant(domain=d, technique=t) for d, t in deduped]
        variants.sort(key=lambda v: v.domain)
        return variants

    def _valid(self, base: str) -> Optional[str]:
        if not base or base == self.base:
            return None
        domain = f"{base}.{self.tld}"
        if domain in self._seen:
            return None
        return domain

    def _gen_keyword_suffixes(self) -> List[Tuple[str, str]]:
        out = []
        for kw in PHISHING_KEYWORDS:
            for candidate in (f"{self.base}-{kw}", f"{kw}-{self.base}", f"{self.base}{kw}"):
                d = self._valid(candidate)
                if d:
                    out.append((d, "keyword"))
        return out

    def _gen_tld_swap(self) -> List[Tuple[str, str]]:
        out = []
        for tld in COMMON_TLDS:
            if tld == self.tld:
                continue
            domain = f"{self.base}.{tld}"
            if domain != self.target_domain:
                out.append((domain, "tld_swap"))
        return out

    def _gen_homoglyphs(self) -> List[Tuple[str, str]]:
        out = []
        base = self.base
        for i, char in enumerate(base):
            for repl in HOMOGLYPHS.get(char, []):
                d = self._valid(base[:i] + repl + base[i + 1:])
                if d:
                    out.append((d, "homoglyph"))
        return out

    def _gen_transpositions(self) -> List[Tuple[str, str]]:
        out = []
        base = self.base
        for i in range(len(base) - 1):
            d = self._valid(base[:i] + base[i + 1] + base[i] + base[i + 2:])
            if d:
                out.append((d, "transposition"))
        return out

    def _gen_omissions(self) -> List[Tuple[str, str]]:
        out = []
        base = self.base
        for i in range(len(base)):
            d = self._valid(base[:i] + base[i + 1:])
            if d:
                out.append((d, "omission"))
        return out

    def _gen_insertions(self) -> List[Tuple[str, str]]:
        out = []
        base = self.base
        common_chars = 'abcdefghijklmnopqrstuvwxyz0123456789-'
        for i in range(len(base) + 1):
            for ch in common_chars:
                d = self._valid(base[:i] + ch + base[i:])
                if d:
                    out.append((d, "insertion"))
        return out


# ----------------------------------------------------------------------
# DNS Checker (asíncrono)
# ----------------------------------------------------------------------
class DNSChecker:
    """Realiza resoluciones DNS asíncronas (A y MX) con control de concurrencia."""

    def __init__(self, concurrency: int, timeout: float, nameservers: Optional[List[str]] = None):
        self.semaphore = asyncio.Semaphore(concurrency)
        self.resolver = dns.asyncresolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
        if nameservers:
            self.resolver.nameservers = nameservers

    async def check_domain(self, variant: DomainVariant) -> None:
        async with self.semaphore:
            variant.status = "checking"
            try:
                ips: List[str] = []
                has_a = False
                try:
                    answers_a = await self.resolver.resolve(variant.domain, 'A')
                    ips = [str(r) for r in answers_a]
                    has_a = True
                except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                    variant.status = "available"
                    variant.risk_level = "DISPONIBLE"
                    return
                except dns.resolver.NoAnswer:
                    pass
                except Exception:
                    variant.status = "available"
                    variant.risk_level = "DISPONIBLE"
                    return

                mx_servers: List[str] = []
                has_mx = False
                try:
                    answers_mx = await self.resolver.resolve(variant.domain, 'MX')
                    mx_servers = [str(r.exchange) for r in answers_mx]
                    has_mx = True
                except Exception:
                    pass

                if has_a and has_mx:
                    variant.status, variant.risk_level = "critical", "CRÍTICO"
                    variant.ip, variant.mx_servers = ips[0] if ips else None, mx_servers
                elif has_a:
                    variant.status, variant.risk_level = "high", "ALTO"
                    variant.ip = ips[0] if ips else None
                elif has_mx:
                    variant.status, variant.risk_level = "high", "ALTO"
                    variant.mx_servers = mx_servers
                else:
                    variant.status, variant.risk_level = "available", "DISPONIBLE"

            except Exception as e:
                variant.status = "error"
                variant.error = str(e)
                variant.risk_level = "ERROR"


# ----------------------------------------------------------------------
# WHOIS Checker (opcional) — antigüedad de registro
# ----------------------------------------------------------------------
class WhoisChecker:
    """Consulta WHOIS solo para dominios ya confirmados como registrados
    (has A o MX), ya que WHOIS es lento y a menudo tiene rate limiting."""

    def __init__(self, concurrency: int = WHOIS_CONCURRENCY):
        self.semaphore = asyncio.Semaphore(concurrency)

    async def enrich(self, variant: DomainVariant) -> None:
        if not _HAS_WHOIS:
            return
        if variant.status not in ("high", "critical"):
            return
        async with self.semaphore:
            loop = asyncio.get_running_loop()
            try:
                data = await loop.run_in_executor(None, whois_lib.whois, variant.domain)
                created = data.creation_date
                if isinstance(created, list):
                    created = created[0] if created else None
                if created:
                    from datetime import datetime, timezone
                    if created.tzinfo is None:
                        now = datetime.now()
                    else:
                        now = datetime.now(timezone.utc)
                    days = (now - created).days
                    variant.created_date = str(created)
                    variant.days_since_registration = days
                    if days is not None and days <= RECENTLY_REGISTERED_DAYS:
                        variant.recently_registered = True
                        if variant.risk_level == "ALTO":
                            variant.risk_level = "ALTO (registro reciente)"
                        elif variant.risk_level == "CRÍTICO":
                            variant.risk_level = "CRÍTICO (registro reciente)"
            except Exception:
                # WHOIS falla frecuentemente (rate limit, formatos raros): no debe romper el flujo
                pass


# ----------------------------------------------------------------------
# Certificate Transparency Checker (opcional) — crt.sh
# ----------------------------------------------------------------------
class CertTransparencyChecker:
    """Busca en los logs públicos de Certificate Transparency (crt.sh)
    dominios reales (no generados por typosquatting) que tengan certificados
    SSL emitidos mencionando la marca/base del objetivo. Esto detecta
    infraestructura de phishing que no necesariamente es un typosquat obvio."""

    URL = "https://crt.sh/?q=%25{query}%25&output=json"

    async def search(self, base: str, legit_domain: str, timeout: float = 10.0) -> List[str]:
        if not _HAS_AIOHTTP:
            return []
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(self.URL.format(query=base), timeout=timeout) as resp:
                    if resp.status != 200:
                        return []
                    text = await resp.text()
                    try:
                        rows = json.loads(text)
                    except json.JSONDecodeError:
                        return []
        except Exception:
            return []

        found: Set[str] = set()
        for row in rows:
            name_value = row.get("name_value", "")
            for name in name_value.split("\n"):
                name = name.strip().lower().lstrip("*.")
                if name and name != legit_domain and not name.endswith("." + legit_domain):
                    found.add(name)
        return sorted(found)


# ----------------------------------------------------------------------
# TUI (Rich)
# ----------------------------------------------------------------------
class TUIConsole:
    """Renderiza la vista en vivo (optimizada: solo lo relevante + progreso
    global) y las tablas finales."""

    def __init__(self, console: Console):
        self.console = console
        self.results: List[DomainVariant] = []
        self.total = 0
        self.progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]Escaneando dominios..."),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=console,
        )
        self.progress_task_id = None
        self.live: Optional[Live] = None

    def set_results(self, results: List[DomainVariant]):
        self.results = results
        self.total = len(results)
        self.progress_task_id = self.progress.add_task("scan", total=self.total)

    def _style_for(self, variant: DomainVariant) -> str:
        return {
            "critical": "bold red",
            "high": "bold yellow",
            "available": "green",
            "error": "red",
            "checking": "cyan",
        }.get(variant.status, "white")

    def _build_table(self, variants: List[DomainVariant], title: str) -> Table:
        table = Table(title=title, box=box.SIMPLE_HEAVY, header_style="bold cyan", show_lines=False)
        table.add_column("Dominio", style="white", no_wrap=True)
        table.add_column("Técnica", style="dim")
        table.add_column("Estado", justify="center", style="bold")
        table.add_column("IP", style="magenta")
        table.add_column("MX", style="blue")
        table.add_column("Registrado", style="dim")
        table.add_column("Riesgo", justify="center", style="bold")

        for v in variants:
            table.add_row(
                v.domain,
                v.technique,
                v.status.upper(),
                v.ip or "—",
                ", ".join(v.mx_servers) if v.mx_servers else "—",
                (v.created_date[:10] if v.created_date else "—"),
                v.risk_level if v.risk_level != "UNKNOWN" else "—",
                style=self._style_for(v),
            )
        return table

    def _renderable(self) -> Group:
        done = sum(1 for v in self.results if v.status not in ("pending", "checking"))
        self.progress.update(self.progress_task_id, completed=done)

        interesting = [v for v in self.results if v.status in ("critical", "high")]
        interesting.sort(key=lambda v: v.severity)
        table = self._build_table(interesting[:25], "Hallazgos de riesgo (en vivo)")

        counts = self._counts()
        summary = Panel(
            f"[bold]Analizadas:[/] {done}/{self.total}   "
            f"[bold red]Crítico:[/] {counts['critical']}   "
            f"[bold yellow]Alto:[/] {counts['high']}   "
            f"[green]Disponible:[/] {counts['available']}   "
            f"[red]Error:[/] {counts['error']}",
            border_style="cyan",
        )
        return Group(self.progress, summary, table)

    def _counts(self) -> dict:
        c = {"critical": 0, "high": 0, "available": 0, "error": 0}
        for v in self.results:
            if v.status in c:
                c[v.status] += 1
        return c

    def start_live(self):
        self.live = Live(self._renderable(), console=self.console, refresh_per_second=8)
        self.live.start()

    def refresh(self):
        if self.live:
            self.live.update(self._renderable())

    def stop_live(self):
        if self.live:
            self.live.stop()

    async def display_loop(self, interval: float = 0.25):
        while True:
            self.refresh()
            await asyncio.sleep(interval)


# ----------------------------------------------------------------------
# Orquestador principal
# ----------------------------------------------------------------------
class PhishTracker:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.target_domain = args.domain
        self.console = Console()
        self.engine = TyposquatEngine(self.target_domain, args.max_variants)
        nameservers = args.nameservers.split(",") if args.nameservers else None
        self.checker = DNSChecker(args.concurrency, args.timeout, nameservers)
        self.whois_checker = WhoisChecker() if args.whois else None
        self.crtsh_checker = CertTransparencyChecker() if args.crtsh else None
        self.tui = TUIConsole(self.console)
        self.results: List[DomainVariant] = []
        self.crtsh_hits: List[str] = []
        self._interrupted = False

    def _install_signal_handlers(self, loop: asyncio.AbstractEventLoop):
        def _handler():
            self._interrupted = True
            self.console.print("\n[bold yellow]⚠ Interrupción recibida. Cancelando tareas pendientes...[/]")
        try:
            loop.add_signal_handler(signal.SIGINT, _handler)
        except NotImplementedError:
            # add_signal_handler no está disponible en algunas plataformas (ej. Windows)
            pass

    async def run(self):
        self._print_banner()

        if not _HAS_TLDEXTRACT:
            self.console.print("[dim]Sugerencia: instala 'tldextract' para manejar TLDs compuestos (co.uk, com.ar, etc.)[/]")
        if self.args.whois and not _HAS_WHOIS:
            self.console.print("[yellow]Aviso: --whois solicitado pero 'python-whois' no está instalado. Se omitirá.[/]")
        if self.args.crtsh and not _HAS_AIOHTTP:
            self.console.print("[yellow]Aviso: --crtsh solicitado pero 'aiohttp' no está instalado. Se omitirá.[/]")

        self.console.print("[bold cyan]Generando variaciones...[/]")
        self.results = self.engine.generate()
        if not self.results:
            self.console.print("[bold red]No se generaron variaciones.[/]")
            return
        self.console.print(f"[green]Se generaron {len(self.results)} variaciones (de un espacio combinatorio mayor, priorizadas).[/]\n")

        loop = asyncio.get_running_loop()
        self._install_signal_handlers(loop)

        self.tui.set_results(self.results)
        self.tui.start_live()
        display_task = asyncio.create_task(self.tui.display_loop())

        dns_tasks = [asyncio.create_task(self.checker.check_domain(v)) for v in self.results]
        try:
            await asyncio.gather(*dns_tasks, return_exceptions=True)

            if self.whois_checker and not self._interrupted:
                whois_tasks = [asyncio.create_task(self.whois_checker.enrich(v)) for v in self.results
                               if v.status in ("high", "critical")]
                if whois_tasks:
                    self.tui.progress.update(self.tui.progress_task_id, description="Consultando WHOIS...")
                    await asyncio.gather(*whois_tasks, return_exceptions=True)
        finally:
            display_task.cancel()
            try:
                await display_task
            except asyncio.CancelledError:
                pass
            self.tui.stop_live()

        if self.crtsh_checker and not self._interrupted:
            self.console.print("[bold cyan]Consultando Certificate Transparency (crt.sh)...[/]")
            self.crtsh_hits = await self.crtsh_checker.search(self.engine.base, self.target_domain)

        self._print_final_report()
        self._export(self.args.output)

    def _print_banner(self):
        ascii_art = r"""
        ____  _     _      _     _____               _
       |  _ \| |   (_)    | |   |_   _|             | |
       | |_) | |__  _ ___ | |__   | |_ __ __ _  ___| | _____ _ __
       |  __/| '_ \| / __|| '_ \  | | '__/ _` |/ __| |/ / _ \ '__|
       | |   | | | | \__ \| | | | | | | | (_| | (__|   <  __/ |
       |_|   |_| |_|_|___/|_| |_| |_|_|  \__,_|\___|_|\_\___|_|
        """
        self.console.print(ascii_art, style="bold red")
        self.console.print(Panel.fit(
            "[bold cyan]PHISH-TRACKER // Threat Intel & Typosquatting Watcher[/]\n"
            f"[bold]Objetivo:[/] {self.target_domain}\n"
            f"[bold]Máx. variantes:[/] {self.args.max_variants}   "
            f"[bold]Concurrencia:[/] {self.args.concurrency}   "
            f"[bold]Timeout:[/] {self.args.timeout}s",
            border_style="red", padding=(1, 2),
        ))
        self.console.print()

    def _print_final_report(self):
        registered = [v for v in self.results if v.status in ("high", "critical")]
        registered.sort(key=lambda v: v.severity)
        if registered:
            self.console.print(self.tui._build_table(registered, "Dominios registrados (riesgo ALTO/CRÍTICO)"))
        else:
            self.console.print("[green]No se encontraron dominios registrados en riesgo.[/]")

        if self.crtsh_checker:
            if self.crtsh_hits:
                self.console.print(Panel(
                    "\n".join(self.crtsh_hits[:30]) + (f"\n... y {len(self.crtsh_hits) - 30} más" if len(self.crtsh_hits) > 30 else ""),
                    title=f"⚠ Certificados SSL sospechosos hallados en crt.sh ({len(self.crtsh_hits)})",
                    border_style="red",
                ))
            else:
                self.console.print("[dim]crt.sh: no se hallaron certificados adicionales sospechosos.[/]")

        counts = self.tui._counts()
        self.console.print(Panel(
            f"[bold]Total analizadas:[/] {len(self.results)}\n"
            f"[bold]Registradas (ALTO+CRÍTICO):[/] {counts['high'] + counts['critical']}\n"
            f"[bold red]En riesgo CRÍTICO:[/] {counts['critical']}\n"
            f"[bold yellow]En riesgo ALTO:[/] {counts['high']}\n"
            f"[green]Disponibles:[/] {counts['available']}\n"
            f"[red]Errores:[/] {counts['error']}\n"
            f"[bold]Recién registrados (<{RECENTLY_REGISTERED_DAYS}d):[/] "
            f"{sum(1 for v in self.results if v.recently_registered)}",
            title="Informe Final", border_style="cyan",
        ))

    def _export(self, output_prefix: str):
        summary = {
            "target_domain": self.target_domain,
            "total_variants": len(self.results),
            "registered": sum(1 for r in self.results if r.status in ("high", "critical")),
            "critical": sum(1 for r in self.results if r.status == "critical"),
            "high": sum(1 for r in self.results if r.status == "high"),
            "available": sum(1 for r in self.results if r.status == "available"),
            "errors": sum(1 for r in self.results if r.status == "error"),
            "recently_registered": sum(1 for r in self.results if r.recently_registered),
        }
        report = {
            "summary": summary,
            "certificate_transparency_hits": self.crtsh_hits,
            "results": [
                {
                    "domain": r.domain,
                    "technique": r.technique,
                    "status": r.status,
                    "ip": r.ip,
                    "mx_servers": r.mx_servers,
                    "risk_level": r.risk_level,
                    "created_date": r.created_date,
                    "days_since_registration": r.days_since_registration,
                    "recently_registered": r.recently_registered,
                    "error": r.error,
                }
                for r in self.results
            ],
        }

        json_path = f"{output_prefix}.json"
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        csv_path = f"{output_prefix}.csv"
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["domain", "technique", "status", "risk_level", "ip", "mx_servers",
                              "created_date", "days_since_registration", "recently_registered", "error"])
            for r in self.results:
                writer.writerow([r.domain, r.technique, r.status, r.risk_level, r.ip or "",
                                  ";".join(r.mx_servers), r.created_date or "",
                                  r.days_since_registration or "", r.recently_registered, r.error or ""])

        self.console.print(f"\n[bold green]Reporte exportado a {json_path} y {csv_path}[/]")


# ----------------------------------------------------------------------
# CLI / Entry point
# ----------------------------------------------------------------------
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="phish-tracker",
        description="Detecta dominios typosquatted y posible infraestructura de phishing.",
    )
    parser.add_argument("domain", help="Dominio objetivo, ej. example.com")
    parser.add_argument("--max-variants", type=int, default=MAX_VARIANTS_DEFAULT,
                         help=f"Máximo de variantes a analizar (default: {MAX_VARIANTS_DEFAULT})")
    parser.add_argument("--concurrency", type=int, default=CONCURRENT_DNS_QUERIES_DEFAULT,
                         help=f"Consultas DNS concurrentes (default: {CONCURRENT_DNS_QUERIES_DEFAULT})")
    parser.add_argument("--timeout", type=float, default=DNS_TIMEOUT_DEFAULT,
                         help=f"Timeout DNS en segundos (default: {DNS_TIMEOUT_DEFAULT})")
    parser.add_argument("--nameservers", type=str, default=None,
                         help="Lista de nameservers separados por coma, ej. 1.1.1.1,8.8.8.8")
    parser.add_argument("--whois", action="store_true",
                         help="Consulta WHOIS en dominios registrados para detectar registros recientes (más lento)")
    parser.add_argument("--crtsh", action="store_true",
                         help="Busca en Certificate Transparency (crt.sh) infraestructura adicional")
    parser.add_argument("--output", type=str, default="phish_report",
                         help="Prefijo de los archivos de salida (default: phish_report -> .json/.csv)")
    return parser.parse_args()


def validate_domain(domain: str) -> str:
    domain = domain.strip().lower()
    if not domain or '.' not in domain or domain.startswith('.') or domain.endswith('.'):
        print("Error: el dominio debe tener un formato válido (ej. example.com)")
        sys.exit(1)
    return domain


async def main():
    args = parse_args()
    args.domain = validate_domain(args.domain)
    tracker = PhishTracker(args)
    await tracker.run()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupción del usuario. Saliendo...")
        sys.exit(0)
