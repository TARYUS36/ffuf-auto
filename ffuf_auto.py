#!/usr/bin/env python3
"""
ffuf-auto — parallel recon TUI for ffuf.

Runs vhost, subdomain and directory fuzzing concurrently, renders live results
in a three-panel terminal UI, and writes a JSON + Markdown report to disk.

For authorised security testing and CTF practice only.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from queue import Empty, Queue

from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

__version__ = "2.0.0"

SCAN_TYPES = ("vhost", "subdomain", "directory")

PANEL_TITLES = {
    "vhost": "VHost Enumeration",
    "subdomain": "Subdomain Enumeration",
    "directory": "Directory Brute Force",
}

STATUS_STYLES = {
    "queued": "dim",
    "running": "yellow",
    "done": "green",
    "failed": "bold red",
    "cancelled": "magenta",
}

DEFAULT_SUB_WORDLIST = "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
DEFAULT_DIR_WORDLIST = (
    "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt"
)

MAX_PANEL_LINES = 500
STDERR_RING = 20


class PreflightError(RuntimeError):
    """Raised when the environment is not ready to run any scans."""


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #


@dataclass
class Finding:
    """A single ffuf hit, normalised across scan types."""

    scan: str
    target: str
    payload: str
    status: int
    length: int
    words: int
    lines: int
    redirect: str = ""

    def as_line(self) -> str:
        """Rich-markup line for the live panel. Everything dynamic is escaped."""
        if 200 <= self.status < 300:
            style = "green"
        elif 300 <= self.status < 400:
            style = "cyan"
        elif 400 <= self.status < 500:
            style = "yellow"
        else:
            style = "red"
        return (
            f"[{style}]\\[{self.status}][/{style}] {escape(self.target)} "
            f"[dim](size={self.length}, words={self.words})[/dim]"
        )

    def as_dict(self) -> dict:
        return {
            "scan": self.scan,
            "target": self.target,
            "payload": self.payload,
            "status": self.status,
            "length": self.length,
            "words": self.words,
            "lines": self.lines,
            "redirect": self.redirect,
        }


@dataclass
class ScanConfig:
    """Everything needed to build and run a set of ffuf commands."""

    host: str
    scheme: str = "http"
    port: int | None = None
    wordlists: dict[str, Path] = field(default_factory=dict)
    filter_size: dict[str, int] = field(default_factory=dict)
    match_codes: str | None = None
    filter_codes: str | None = None
    filter_words: str | None = None
    filter_regex: str | None = None
    threads: int = 40
    rate: int = 0
    timeout: int = 10
    auto_calibrate: bool = False
    stagger: float = 0.0
    scans: tuple[str, ...] = SCAN_TYPES
    extra: list[str] = field(default_factory=list)
    output_dir: Path = Path("results")

    @property
    def port_suffix(self) -> str:
        """':8443' — empty when the port is the scheme default or unset."""
        if self.port is None:
            return ""
        if (self.scheme == "http" and self.port == 80) or (
            self.scheme == "https" and self.port == 443
        ):
            return ""
        return f":{self.port}"

    @property
    def authority(self) -> str:
        return f"{self.host}{self.port_suffix}"

    @property
    def base_url(self) -> str:
        return f"{self.scheme}://{self.authority}"


# --------------------------------------------------------------------------- #
# Command building  (pure function — unit tested in tests/)
# --------------------------------------------------------------------------- #


def build_command(cfg: ScanConfig, scan: str) -> list[str]:
    """Translate a ScanConfig into a concrete ffuf argv for one scan type."""
    if scan not in SCAN_TYPES:
        raise ValueError(f"unknown scan type: {scan!r}")

    cmd = ["ffuf", "-json", "-s", "-ic"]

    if scan == "vhost":
        cmd += [
            "-w", str(cfg.wordlists["subdomain"]),
            "-u", f"{cfg.base_url}/",
            "-H", f"Host: FUZZ.{cfg.authority}",
        ]
    elif scan == "subdomain":
        cmd += [
            "-w", str(cfg.wordlists["subdomain"]),
            "-u", f"{cfg.scheme}://FUZZ.{cfg.authority}/",
        ]
    else:  # directory
        cmd += [
            "-w", str(cfg.wordlists["directory"]),
            "-u", f"{cfg.base_url}/FUZZ",
        ]

    if scan in cfg.filter_size:
        cmd += ["-fs", str(cfg.filter_size[scan])]
    if cfg.auto_calibrate:
        cmd.append("-ac")
    if cfg.match_codes:
        cmd += ["-mc", cfg.match_codes]
    if cfg.filter_codes:
        cmd += ["-fc", cfg.filter_codes]
    if cfg.filter_words:
        cmd += ["-fw", cfg.filter_words]
    if cfg.filter_regex:
        cmd += ["-fr", cfg.filter_regex]

    cmd += ["-t", str(cfg.threads), "-timeout", str(cfg.timeout)]
    if cfg.rate > 0:
        cmd += ["-rate", str(cfg.rate)]

    cmd += cfg.extra
    return cmd


# --------------------------------------------------------------------------- #
# Preflight — fail loudly *before* the TUI takes over the screen
# --------------------------------------------------------------------------- #


def preflight(cfg: ScanConfig) -> None:
    """Verify ffuf, wordlists and the output directory. Raises PreflightError."""
    if shutil.which("ffuf") is None:
        raise PreflightError(
            "ffuf was not found in $PATH.\n"
            "  Install it with:  go install github.com/ffuf/ffuf/v2@latest\n"
            "  or:               sudo apt install ffuf"
        )

    needed: set[str] = set()
    if "vhost" in cfg.scans or "subdomain" in cfg.scans:
        needed.add("subdomain")
    if "directory" in cfg.scans:
        needed.add("directory")

    for key in sorted(needed):
        path = cfg.wordlists.get(key)
        if path is None:
            raise PreflightError(f"no {key} wordlist configured")
        if not path.exists():
            raise PreflightError(
                f"{key} wordlist does not exist: {path}\n"
                f"  Pass a valid path with --{key}-wordlist, or install SecLists:\n"
                f"  sudo apt install seclists"
            )
        if not path.is_file():
            raise PreflightError(f"{key} wordlist is not a file: {path}")
        if path.stat().st_size == 0:
            raise PreflightError(f"{key} wordlist is empty: {path}")

    try:
        cfg.output_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise PreflightError(f"cannot create output directory {cfg.output_dir}: {exc}") from exc


# --------------------------------------------------------------------------- #
# Runner
# --------------------------------------------------------------------------- #


class FFufAuto:
    def __init__(self, cfg: ScanConfig, console: Console | None = None) -> None:
        self.cfg = cfg
        self.console = console or Console()
        self.scans = tuple(cfg.scans)

        self.queues: dict[str, Queue] = {s: Queue() for s in self.scans}
        self.findings: dict[str, list[Finding]] = {s: [] for s in self.scans}
        self.lines: dict[str, list[str]] = {s: [] for s in self.scans}
        self.errors: dict[str, deque] = {s: deque(maxlen=STDERR_RING) for s in self.scans}
        self.status: dict[str, str] = {s: "queued" for s in self.scans}

        self._procs: dict[str, subprocess.Popen] = {}
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self.started_at = datetime.now()
        self.finished_at: datetime | None = None

    # -- scan execution ----------------------------------------------------- #

    def _drain_stderr(self, scan: str, pipe) -> None:
        """Keep the last few stderr lines so a failing ffuf can explain itself."""
        try:
            for raw in iter(pipe.readline, ""):
                line = raw.strip()
                if line:
                    self.errors[scan].append(line)
        except (ValueError, OSError):
            pass
        finally:
            try:
                pipe.close()
            except OSError:
                pass

    def _to_finding(self, scan: str, data: dict) -> Finding:
        payload = data.get("input", "")
        if isinstance(payload, dict):
            payload = payload.get("FUZZ", next(iter(payload.values()), ""))

        if scan == "vhost":
            target = data.get("host") or f"{payload}.{self.cfg.authority}"
        else:
            target = data.get("url", "?")

        def _int(key: str) -> int:
            try:
                return int(data.get(key, 0))
            except (TypeError, ValueError):
                return 0

        return Finding(
            scan=scan,
            target=str(target),
            payload=str(payload),
            status=_int("status"),
            length=_int("length"),
            words=_int("words"),
            lines=_int("lines"),
            redirect=str(data.get("redirectlocation", "") or ""),
        )

    def run_scan(self, scan: str, delay: float = 0.0) -> None:
        """Worker thread: launch ffuf, parse its JSON stream, report failures."""
        if delay and self._stop.wait(delay):
            self.status[scan] = "cancelled"
            return
        if self._stop.is_set():
            self.status[scan] = "cancelled"
            return

        cmd = build_command(self.cfg, scan)
        self.status[scan] = "running"

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,  # keeps ffuf off the shared terminal
                universal_newlines=True,
                bufsize=1,
            )
        except FileNotFoundError:
            self.status[scan] = "failed"
            self.queues[scan].put(("error", "ffuf is no longer available in $PATH"))
            return
        except OSError as exc:
            self.status[scan] = "failed"
            self.queues[scan].put(("error", f"could not start ffuf: {exc}"))
            return

        with self._lock:
            self._procs[scan] = proc

        err_thread = threading.Thread(
            target=self._drain_stderr, args=(scan, proc.stderr), daemon=True
        )
        err_thread.start()

        try:
            for raw in iter(proc.stdout.readline, ""):
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    data = json.loads(raw)
                except json.JSONDecodeError:
                    continue  # banner / progress noise
                if not isinstance(data, dict) or "status" not in data:
                    continue
                self.queues[scan].put(("hit", self._to_finding(scan, data)))
        except (ValueError, OSError) as exc:
            self.queues[scan].put(("error", f"stdout read failed: {exc}"))
        finally:
            try:
                proc.stdout.close()
            except OSError:
                pass

        returncode = proc.wait()
        err_thread.join(timeout=1.0)

        if self._stop.is_set():
            self.status[scan] = "cancelled"
        elif returncode == 0:
            self.status[scan] = "done"
        else:
            self.status[scan] = "failed"
            self.queues[scan].put(("error", f"ffuf exited with code {returncode}"))
            for line in list(self.errors[scan])[-5:]:
                self.queues[scan].put(("error", line))

    def _terminate_all(self) -> None:
        self._stop.set()
        with self._lock:
            procs = list(self._procs.values())
        for proc in procs:
            if proc.poll() is None:
                proc.terminate()
        for proc in procs:
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()

    # -- rendering ---------------------------------------------------------- #

    def _drain_queues(self) -> None:
        for scan in self.scans:
            queue = self.queues[scan]
            while True:
                try:
                    kind, payload = queue.get_nowait()
                except Empty:
                    break
                if kind == "hit":
                    self.findings[scan].append(payload)
                    self.lines[scan].append(payload.as_line())
                else:
                    self.lines[scan].append(f"[bold red]![/bold red] {escape(str(payload))}")

    def _panel(self, scan: str) -> Panel:
        rendered = self.lines[scan][-MAX_PANEL_LINES:]
        body = "\n".join(rendered) if rendered else "[dim]waiting…[/dim]"
        state = self.status[scan]
        style = STATUS_STYLES.get(state, "white")
        border = {"done": "green", "failed": "red", "cancelled": "magenta"}.get(state, "cyan")
        title = (
            f"[bold cyan]{PANEL_TITLES[scan]}[/bold cyan] "
            f"[dim]({len(self.findings[scan])} hits)[/dim] "
            f"[{style}]{state}[/{style}]"
        )
        return Panel(body, title=title, border_style=border)

    def _header(self) -> Text:
        elapsed = int((datetime.now() - self.started_at).total_seconds())
        return Text(
            f"  {self.cfg.base_url}   ·   "
            + "  ".join(f"{s}: {self.status[s]}" for s in self.scans)
            + f"   ·   {elapsed // 60:02d}:{elapsed % 60:02d}",
            style="bold yellow",
        )

    def _build_layout(self) -> Layout:
        layout = Layout()
        layout.split_column(Layout(name="header", size=1), Layout(name="scans"))
        layout["scans"].split_row(*(Layout(name=s) for s in self.scans))
        return layout

    def _refresh(self, layout: Layout) -> None:
        layout["header"].update(self._header())
        for scan in self.scans:
            layout[scan].update(self._panel(scan))

    # -- persistence -------------------------------------------------------- #

    def save(self) -> tuple[Path, Path]:
        stamp = self.started_at.strftime("%Y%m%d-%H%M%S")
        slug = "".join(c if c.isalnum() or c in "._-" else "_" for c in self.cfg.host)
        run_dir = self.cfg.output_dir / f"{slug}_{stamp}"
        run_dir.mkdir(parents=True, exist_ok=True)

        report = {
            "tool": "ffuf-auto",
            "version": __version__,
            "target": self.cfg.base_url,
            "host": self.cfg.host,
            "started_at": self.started_at.isoformat(timespec="seconds"),
            "finished_at": (self.finished_at or datetime.now()).isoformat(timespec="seconds"),
            "status": dict(self.status),
            "commands": {s: build_command(self.cfg, s) for s in self.scans},
            "results": {s: [f.as_dict() for f in self.findings[s]] for s in self.scans},
            "stderr": {s: list(self.errors[s]) for s in self.scans},
        }

        json_path = run_dir / "results.json"
        json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

        md_path = run_dir / "report.md"
        md_path.write_text(self._markdown(report), encoding="utf-8")

        return json_path, md_path

    def _markdown(self, report: dict) -> str:
        out: list[str] = [
            f"# ffuf-auto report — {report['target']}",
            "",
            f"- **Started:** {report['started_at']}",
            f"- **Finished:** {report['finished_at']}",
            f"- **Tool version:** {report['version']}",
            "",
        ]
        for scan in self.scans:
            findings = self.findings[scan]
            out += [
                f"## {PANEL_TITLES[scan]}",
                "",
                f"*Status:* `{self.status[scan]}` — {len(findings)} hit(s)",
                "",
                "```",
                " ".join(report["commands"][scan]),
                "```",
                "",
            ]
            if findings:
                out += [
                    "| Status | Target | Size | Words | Lines |",
                    "|---|---|---|---|---|",
                ]
                out += [
                    f"| {f.status} | `{f.target}` | {f.length} | {f.words} | {f.lines} |"
                    for f in findings
                ]
            else:
                out.append("_No results._")
            if self.status[scan] == "failed" and self.errors[scan]:
                out += ["", "**stderr:**", "", "```"]
                out += list(self.errors[scan])
                out.append("```")
            out.append("")
        return "\n".join(out)

    # -- summary (small, deliberately not a dump of the panels) ------------- #

    def print_summary(self, json_path: Path, md_path: Path) -> None:
        table = Table(title=f"ffuf-auto — {self.cfg.base_url}", title_style="bold cyan")
        table.add_column("Scan", style="cyan")
        table.add_column("Status")
        table.add_column("Hits", justify="right")
        for scan in self.scans:
            state = self.status[scan]
            table.add_row(
                PANEL_TITLES[scan],
                f"[{STATUS_STYLES.get(state, 'white')}]{state}[/]",
                str(len(self.findings[scan])),
            )
        self.console.print()
        self.console.print(table)

        failed = [s for s in self.scans if self.status[s] == "failed"]
        for scan in failed:
            self.console.print(f"[bold red]{scan} failed:[/bold red]")
            for line in list(self.errors[scan])[-5:]:
                self.console.print(f"  [red]{escape(line)}[/red]")

        self.console.print(f"\n[bold]JSON  :[/bold] {json_path}")
        self.console.print(f"[bold]Report:[/bold] {md_path}\n")

    # -- entry point -------------------------------------------------------- #

    def run(self) -> int:
        threads = [
            threading.Thread(
                target=self.run_scan, args=(scan, i * self.cfg.stagger), daemon=True
            )
            for i, scan in enumerate(self.scans)
        ]
        for thread in threads:
            thread.start()

        layout = self._build_layout()
        interrupted = False

        try:
            with Live(layout, refresh_per_second=4, screen=True, console=self.console):
                while any(t.is_alive() for t in threads):
                    self._drain_queues()
                    self._refresh(layout)
                    time.sleep(0.25)
                self._drain_queues()
                self._refresh(layout)
                time.sleep(0.8)
        except KeyboardInterrupt:
            interrupted = True
            self._terminate_all()
            for thread in threads:
                thread.join(timeout=3)
            self._drain_queues()
        finally:
            self.finished_at = datetime.now()
            json_path, md_path = self.save()

        if interrupted:
            self.console.print(
                "\n[bold magenta]Interrupted — partial results saved.[/bold magenta]"
            )
        self.print_summary(json_path, md_path)

        return 1 if any(self.status[s] == "failed" for s in self.scans) else 0


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="ffuf-auto",
        description="Run vhost, subdomain and directory fuzzing in parallel.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  %(prog)s target.htb
  %(prog)s target.htb -ac
  %(prog)s target.htb -fsV 400 -fsS 300 -fsD 1234
  %(prog)s target.htb --scheme https --port 8443 --scans vhost directory
  %(prog)s target.htb -t 10 --rate 50 --stagger 5
  %(prog)s target.htb --ffuf-arg -e --ffuf-arg .php,.bak

Use only against systems you own or are authorised to test.
""",
    )

    parser.add_argument("host", help="target host, e.g. target.htb")
    parser.add_argument("--scheme", choices=("http", "https"), default="http")
    parser.add_argument("--port", type=int, help="target port")
    parser.add_argument(
        "--scans", nargs="+", choices=SCAN_TYPES, default=list(SCAN_TYPES),
        help="which scans to run (default: all)",
    )

    wl = parser.add_argument_group("wordlists")
    wl.add_argument("-w", "--subdomain-wordlist", default=DEFAULT_SUB_WORDLIST,
                    help="wordlist for vhost + subdomain scans")
    wl.add_argument("-W", "--directory-wordlist", default=DEFAULT_DIR_WORDLIST,
                    help="wordlist for the directory scan")

    flt = parser.add_argument_group("filters")
    flt.add_argument("-fsV", "--filter-vhost", type=int, help="response-size filter, vhost")
    flt.add_argument("-fsS", "--filter-sub", type=int, help="response-size filter, subdomain")
    flt.add_argument("-fsD", "--filter-dir", type=int, help="response-size filter, directory")
    flt.add_argument("-ac", "--auto-calibrate", action="store_true",
                     help="let ffuf auto-calibrate filters (usually beats guessing -fs)")
    flt.add_argument("-mc", "--match-codes", help="match HTTP status codes, e.g. 200,301")
    flt.add_argument("-fc", "--filter-codes", help="filter HTTP status codes")
    flt.add_argument("-fw", "--filter-words", help="filter by word count")
    flt.add_argument("-fr", "--filter-regex", help="filter by regex")

    perf = parser.add_argument_group("performance")
    perf.add_argument("-t", "--threads", type=int, default=40, help="ffuf threads per scan")
    perf.add_argument("--rate", type=int, default=0, help="requests/sec per scan (0 = unlimited)")
    perf.add_argument("--timeout", type=int, default=10, help="ffuf request timeout (s)")
    perf.add_argument("--stagger", type=float, default=0.0,
                      help="seconds between launching each scan")

    parser.add_argument("-o", "--output-dir", default="results", help="where reports are written")
    parser.add_argument("--ffuf-arg", action="append", default=[], dest="ffuf_args",
                        help="raw argument forwarded to ffuf (repeatable)")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    return parser.parse_args(argv)


def config_from_args(args: argparse.Namespace) -> ScanConfig:
    filter_size: dict[str, int] = {}
    if args.filter_vhost is not None:
        filter_size["vhost"] = args.filter_vhost
    if args.filter_sub is not None:
        filter_size["subdomain"] = args.filter_sub
    if args.filter_dir is not None:
        filter_size["directory"] = args.filter_dir

    return ScanConfig(
        host=args.host,
        scheme=args.scheme,
        port=args.port,
        wordlists={
            "subdomain": Path(args.subdomain_wordlist).expanduser(),
            "directory": Path(args.directory_wordlist).expanduser(),
        },
        filter_size=filter_size,
        match_codes=args.match_codes,
        filter_codes=args.filter_codes,
        filter_words=args.filter_words,
        filter_regex=args.filter_regex,
        threads=args.threads,
        rate=args.rate,
        timeout=args.timeout,
        auto_calibrate=args.auto_calibrate,
        stagger=args.stagger,
        scans=tuple(dict.fromkeys(args.scans)),
        extra=list(args.ffuf_args),
        output_dir=Path(args.output_dir).expanduser(),
    )


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    cfg = config_from_args(args)
    console = Console()

    console.print(f"\n[bold cyan]ffuf-auto[/bold cyan] [dim]v{__version__}[/dim]")
    console.print(f"[bold]Target :[/bold] [cyan]{cfg.base_url}[/cyan]")
    console.print(f"[bold]Scans  :[/bold] {', '.join(cfg.scans)}")
    if cfg.filter_size:
        console.print(
            "[bold]Filters:[/bold] "
            + ", ".join(f"{k} -fs {v}" for k, v in cfg.filter_size.items())
        )
    console.print("[dim]Ctrl+C to cancel — partial results are still written.[/dim]\n")

    try:
        preflight(cfg)
    except PreflightError as exc:
        console.print(f"[bold red]Preflight failed:[/bold red] {exc}\n")
        return 2

    time.sleep(1)
    return FFufAuto(cfg, console=console).run()


if __name__ == "__main__":
    sys.exit(main())
