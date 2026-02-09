"""Rich output formatting for spray results — Catppuccin Mocha themed."""

import ipaddress
from typing import Dict, List, Type

from rich.console import Console
from rich.table import Table
from rich.text import Text

from core.models import Credential, ResultStatus, SprayResult, Target
from core.engine import mask_password
from core.theme import RAPIDS_THEME, MOCHA

console = Console(theme=RAPIDS_THEME)

STATUS_STYLES = {
    ResultStatus.SUCCESS: "success",
    ResultStatus.FAILURE: "failure",
    ResultStatus.ERROR: "error",
    ResultStatus.TIMEOUT: "timeout",
}


STATUS_ORDER = {
    ResultStatus.SUCCESS: 0,
    ResultStatus.FAILURE: 1,
    ResultStatus.ERROR: 2,
    ResultStatus.TIMEOUT: 3,
}


def print_results_table(results: List[SprayResult], show_all: bool = False, elapsed: float = None, mask_creds: bool = False) -> None:
    """Print a Rich table of results."""
    if not results:
        console.print("[warn]No results to display.[/warn]")
        return

    # Only show the full Spray Results table with --show-all
    if show_all:
        display = list(results)
        display.sort(key=lambda r: (r.target.host, STATUS_ORDER.get(r.status, 99), r.service))

        table = Table(
            title="Spray Results",
            show_header=True,
            header_style="table.header",
            border_style=MOCHA["surface2"],
            title_style=f"bold {MOCHA['mauve']}",
        )
        table.add_column("Service", style="table.service")
        table.add_column("Target", style="table.target")
        table.add_column("Username", style="table.user")
        table.add_column("Password", style="table.pass")
        table.add_column("Status", justify="center")
        table.add_column("Message", style="table.msg")

        has_proof = any(r.proof for r in display)
        if has_proof:
            table.add_column("Proof", style="dim")

        for r in display:
            style = STATUS_STYLES.get(r.status, "value")
            pwd = mask_password(r.credential.password) if mask_creds else r.credential.password
            row = [
                r.service,
                str(r.target),
                r.credential.username,
                pwd,
                f"[{style}]{r.status.value}[/{style}]",
                r.message,
            ]
            if has_proof:
                row.append(r.proof or "")
            table.add_row(*row)

        console.print()
        console.print(table)

    print_summary(results, elapsed=elapsed)
    print_valid_creds(results, mask_creds=mask_creds)


def print_summary(results: List[SprayResult], elapsed: float = None) -> None:
    """Print a summary of results by status."""
    counts = {}
    for r in results:
        counts[r.status] = counts.get(r.status, 0) + 1

    console.print(f"\n[heading]Summary:[/heading]")
    for status in ResultStatus:
        count = counts.get(status, 0)
        style = STATUS_STYLES.get(status, "value")
        console.print(f"  [{style}]{status.value}: {count}[/{style}]")
    console.print(f"  [value]Total: {len(results)}[/value]")

    if elapsed is not None:
        minutes, seconds = divmod(elapsed, 60)
        if minutes > 0:
            time_str = f"{int(minutes)}m {seconds:.1f}s"
        else:
            time_str = f"{seconds:.1f}s"
        console.print(f"  [info]Elapsed: {time_str}[/info]")

    # Show error details so user doesn't need --debug
    errors = [r for r in results if r.status == ResultStatus.ERROR]
    if errors:
        console.print(f"\n[heading]Errors:[/heading]")
        seen = set()
        for r in errors:
            key = (r.service, r.target.host, r.target.port, r.message)
            if key in seen:
                continue
            seen.add(key)
            console.print(f"  [error]{r.service}://{r.target} — {r.message}[/error]")

    # Per-host breakdown
    host_hits: Dict[str, List[str]] = {}
    host_total: Dict[str, int] = {}
    for r in results:
        host = r.target.host
        host_total[host] = host_total.get(host, 0) + 1
        if r.status == ResultStatus.SUCCESS:
            host_hits.setdefault(host, []).append(r.service)

    if len(host_total) > 1:
        console.print(f"\n[heading]Per-Host:[/heading]")
        for host in sorted(host_total.keys()):
            hits = host_hits.get(host, [])
            if hits:
                svc_list = ", ".join(sorted(set(hits)))
                console.print(f"  [success]{host}: {len(hits)} hit(s) ({svc_list})[/success]")
            else:
                console.print(f"  [dim]{host}: 0 hits[/dim]")


def print_valid_creds(results: List[SprayResult], mask_creds: bool = False) -> None:
    """Print a clean summary table of only the working credentials."""
    hits = [r for r in results if r.status == ResultStatus.SUCCESS]
    if not hits:
        return

    table = Table(
        title="Valid Credentials",
        show_header=True,
        header_style="table.header",
        border_style=MOCHA["surface2"],
        title_style=f"bold {MOCHA['green']}",
        padding=(0, 1),
    )
    table.add_column("Service", style="table.service")
    table.add_column("Target", style="table.target")
    table.add_column("Username", style="table.user")
    table.add_column("Password", style="table.pass")

    # Add Proof column if any hit has proof data
    has_proof = any(r.proof for r in hits)
    if has_proof:
        table.add_column("Proof", style="dim")

    # One row per service hit, grouped by credential
    # Sort by host, username, then service for clean grouping
    hits.sort(key=lambda r: (r.target.host, r.credential.username, r.credential.password, r.service))

    prev_group = None
    for r in hits:
        group_key = (r.target.host, r.credential.username, r.credential.password)
        is_new_group = group_key != prev_group

        # Add section divider between different credential groups
        if prev_group is not None and is_new_group:
            table.add_section()

        # Show username/password on first row of group, blank on subsequent
        if is_new_group:
            username = r.credential.username
            raw_pwd = r.credential.nthash if r.credential.is_hash else r.credential.password
            password = mask_password(raw_pwd) if mask_creds else raw_pwd
        else:
            username = ""
            password = ""

        row = [
            r.service,
            str(r.target),
            username,
            password,
        ]
        if has_proof:
            row.append(r.proof or "")
        table.add_row(*row)
        prev_group = group_key

    console.print()
    console.print(table)

    # Summary: count unique credentials and total service hits
    unique_creds = len(set(
        (r.target.host, r.credential.username, r.credential.password)
        for r in hits
    ))
    total_hits = len(hits)
    if total_hits != unique_creds:
        console.print(
            f"\n  [success]{unique_creds} unique credential(s) across {total_hits} service(s).[/success]"
        )
    else:
        console.print(
            f"\n  [success]{unique_creds} valid credential(s) found.[/success]"
        )

    # Suggest --verify if no proof was collected
    if not has_proof:
        console.print(
            f"  [dim]Tip: Re-run with --verify to execute proof-of-access commands[/dim]"
        )


def print_dry_run(
    targets: List[Target],
    credentials: List[Credential],
    modules: Dict[str, "Type"],
    port_overrides: Dict[str, int] = None,
    mask_creds: bool = False,
) -> None:
    """Show what would be tested without sending traffic."""
    from modules.base import ServiceModule

    port_overrides = port_overrides or {}

    # Build the same work items the engine would
    work_items = []
    for target in targets:
        if target.service and target.service in modules:
            mod_cls = modules[target.service]
            port = port_overrides.get(target.service, target.port or mod_cls.default_port)
            work_items.append((target.service, target.host, port, target))
        elif not target.service:
            # No service detected: test all modules (manual target)
            for name, mod_cls in modules.items():
                port = port_overrides.get(name, target.port or mod_cls.default_port)
                work_items.append((name, target.host, port, target))

    total = len(work_items) * len(credentials)

    console.print(f"\n[heading]DRY RUN — no traffic will be sent[/heading]\n")

    # Targets table
    tgt_table = Table(
        title="Targets",
        header_style="table.header",
        border_style=MOCHA["surface2"],
        title_style=f"bold {MOCHA['sapphire']}",
    )
    tgt_table.add_column("#", style="dim", justify="right")
    tgt_table.add_column("Host", style="table.target")
    tgt_table.add_column("Port", style="value", justify="right")
    tgt_table.add_column("Service", style="table.service")

    seen_targets = set()
    idx = 0
    for svc, host, port, tgt in work_items:
        key = (host, port, svc)
        if key in seen_targets:
            continue
        seen_targets.add(key)
        idx += 1
        tgt_table.add_row(str(idx), host, str(port), svc)

    console.print(tgt_table)

    # Credentials table
    cred_table = Table(
        title="Credentials",
        header_style="table.header",
        border_style=MOCHA["surface2"],
        title_style=f"bold {MOCHA['sapphire']}",
    )
    cred_table.add_column("#", style="dim", justify="right")
    cred_table.add_column("Username", style="table.user")
    cred_table.add_column("Password", style="table.pass")

    for i, cred in enumerate(credentials, 1):
        pwd = mask_password(cred.password) if mask_creds else cred.password
        cred_table.add_row(str(i), cred.username, pwd)

    console.print()
    console.print(cred_table)

    # Attack plan table
    plan_table = Table(
        title="Attack Plan",
        header_style="table.header",
        border_style=MOCHA["surface2"],
        title_style=f"bold {MOCHA['peach']}",
    )
    plan_table.add_column("#", style="dim", justify="right")
    plan_table.add_column("Service", style="table.service")
    plan_table.add_column("Target", style="table.target")
    plan_table.add_column("Username", style="table.user")
    plan_table.add_column("Password", style="table.pass")

    idx = 0
    for svc, host, port, tgt in work_items:
        for cred in credentials:
            idx += 1
            pwd = mask_password(cred.password) if mask_creds else cred.password
            plan_table.add_row(
                str(idx),
                svc,
                f"{host}:{port}",
                cred.username,
                pwd,
            )

    console.print()
    console.print(plan_table)

    console.print(f"\n  [heading]{total} total attempt(s) planned.[/heading]")
    console.print(f"  [dim]Run without --dry-run to execute.[/dim]\n")


def write_json_output(filepath: str, results: List[SprayResult], elapsed: float = None, mask_creds: bool = False) -> None:
    """Write results to a JSON file for programmatic parsing."""
    import json
    from pathlib import Path

    hits = [r for r in results if r.status == ResultStatus.SUCCESS]

    # Count by status
    counts = {}
    for r in results:
        counts[r.status.value] = counts.get(r.status.value, 0) + 1

    output = {
        "summary": {
            "total": len(results),
            "success": counts.get("SUCCESS", 0),
            "failure": counts.get("FAILURE", 0),
            "error": counts.get("ERROR", 0),
            "timeout": counts.get("TIMEOUT", 0),
            "elapsed_seconds": round(elapsed, 2) if elapsed else None,
        },
        "valid_credentials": [
            {
                "service": r.service,
                "host": r.target.host,
                "port": r.target.port,
                "username": r.credential.username,
                "password": mask_password(r.credential.password) if mask_creds else r.credential.password,
                "proof": r.proof or None,
            }
            for r in hits
        ],
        "all_results": [
            {
                "service": r.service,
                "host": r.target.host,
                "port": r.target.port,
                "username": r.credential.username,
                "password": mask_password(r.credential.password) if mask_creds else r.credential.password,
                "status": r.status.value,
                "message": r.message,
                "proof": r.proof or None,
            }
            for r in results
        ],
    }

    Path(filepath).write_text(json.dumps(output, indent=2))
    console.print(f"\n  [info]Results written to {filepath}[/info]")


def print_scan_results(targets: List[Target]) -> None:
    """Display a Rich table showing discovered hosts/ports/services."""
    if not targets:
        console.print("[warn]No open ports discovered.[/warn]")
        return

    table = Table(
        title="Nmap Scan Results",
        show_header=True,
        header_style="table.header",
        border_style=MOCHA["surface2"],
        title_style=f"bold {MOCHA['teal']}",
    )
    table.add_column("Host", style="table.target")
    table.add_column("Port", style="value", justify="right")
    table.add_column("Service", style="table.service")
    table.add_column("Version", style="dim")
    table.add_column("State", style="success", justify="center")

    def _ip_sort_key(t):
        try:
            return (ipaddress.ip_address(t.host), t.port or 0)
        except ValueError:
            return (ipaddress.ip_address("0.0.0.0"), t.port or 0)

    for target in sorted(targets, key=_ip_sort_key):
        table.add_row(
            target.host,
            str(target.port),
            target.service or "unknown",
            target.version_string or "",
            "open",
        )

    console.print()
    console.print(table)

    # Summary line
    unique_hosts = len(set(t.host for t in targets))
    console.print(f"  [info]Discovered {len(targets)} open port(s) on {unique_hosts} host(s)[/info]\n")


def print_banner() -> None:
    """Print the Rapids banner in Catppuccin Mocha gradient."""
    # Each line gets a different color from the Mocha palette
    colors = [
        MOCHA["mauve"],
        MOCHA["pink"],
        MOCHA["flamingo"],
        MOCHA["peach"],
        MOCHA["yellow"],
        MOCHA["green"],
    ]
    lines = [
        r"  ____             _     _     ",
        r" |  _ \ __ _ _ __ (_) __| |___ ",
        r" | |_) / _` | '_ \| |/ _` / __|",
        " |  _ < (_| | |_) | | (_| \\__ \\",
        r" |_| \_\__,_| .__/|_|\__,_|___/",
        r"            |_|                 ",
    ]
    console.print()
    for line, color in zip(lines, colors):
        console.print(Text(line, style=f"bold {color}"))
    console.print(f"  [{MOCHA['lavender']}]Modular Credential Spraying Tool[/{MOCHA['lavender']}]")
    console.print(f"  [{MOCHA['overlay1']}]For authorized security testing only[/{MOCHA['overlay1']}]\n")
