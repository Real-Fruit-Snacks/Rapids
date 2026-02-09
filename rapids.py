#!/usr/bin/env python3
"""Rapids - Modular Credential Spraying Tool.

For authorized security testing only.
"""

import sys
from pathlib import Path

# Allow running directly with `python rapids.py` without installing
if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).parent))

import click
from rich.console import Console

from core.engine import SprayEngine
from core.input_parser import parse_credentials, parse_nmap_xml, parse_target, parse_targets_file
from core.models import Target
from core.output import print_banner, print_results_table
from core.theme import RAPIDS_THEME
from modules import ModuleRegistry

console = Console(theme=RAPIDS_THEME)


@click.command()
@click.option("-t", "--target", "target_str", multiple=True, help="Target (IP, IP:port, IP:port:service)")
@click.option("-T", "--targets-file", help="File with targets (one per line)")
@click.option("-n", "--nmap", "nmap_xml", help="Nmap XML file for auto-discovery")
@click.option("--no-scan", is_flag=True, help="Disable automatic nmap port/service scan")
@click.option("-u", "--user", help="Single username")
@click.option("-p", "--pass", "password", help="Single password (or NT hash prefixed with ':')")
@click.option("-U", "--userfile", help="Username wordlist file")
@click.option("-P", "--passfile", help="Password wordlist file (supports NT hashes)")
@click.option("-C", "--creds", "credsfile", help="Credentials file (user:pass or user:hash per line)")
@click.option("-s", "--services", help="Comma-separated services to test (default: all)")
@click.option("-w", "--threads", default=10, show_default=True, help="Concurrent threads")
@click.option("--timeout", default=5, show_default=True, help="Connection timeout (seconds)")
@click.option("--delay", default=0.0, show_default=True, help="Delay between attempts (seconds)")
@click.option("-d", "--domain", help="Domain for Kerberos/LDAP/WinRM/SMB")
@click.option("--url-path", default="/", show_default=True, help="URL path for HTTP")
@click.option("--http-form-data", help="POST form template (e.g. 'user=^USER^&pass=^PASS^')")
@click.option("--success-string", help="String indicating successful HTTP form login")
@click.option("--show-all", is_flag=True, help="Show all results including failures")
@click.option("--nxc", is_flag=True, help="Use NetExec (nxc) modules instead of library-based ones")
@click.option("--no-auto-domain", is_flag=True, help="Disable automatic domain discovery")
@click.option("--dry-run", is_flag=True, help="Show what would be tested without sending any traffic")
@click.option("--port", "port_overrides", multiple=True, help="Override service port (e.g. --port ssh=2222)")
@click.option("--verify", is_flag=True, help="Execute proof-of-access command after successful auth")
@click.option("--mask-creds", is_flag=True, help="Mask credentials in all output (for screenshots/screen shares)")
@click.option("--debug", is_flag=True, help="Show raw unformatted output for every attempt")
@click.option("-o", "--output", "output_file", help="Write results to JSON file")
def main(
    target_str,
    targets_file,
    nmap_xml,
    no_scan,
    user,
    password,
    userfile,
    passfile,
    credsfile,
    services,
    threads,
    timeout,
    delay,
    domain,
    url_path,
    http_form_data,
    success_string,
    show_all,
    nxc,
    no_auto_domain,
    dry_run,
    port_overrides,
    verify,
    mask_creds,
    debug,
    output_file,
):
    """Rapids - Modular Credential Spraying Tool.

    Spray credentials across multiple services concurrently.
    For authorized security testing only.
    """
    print_banner()

    # --- Parse port overrides (e.g. --port ssh=2222) ---
    svc_port_map = {}
    for override in port_overrides:
        if "=" not in override:
            console.print(f"[failure]Error: Invalid --port format '{override}'. Use service=port (e.g. ssh=2222)[/failure]")
            sys.exit(1)
        svc, port_str = override.split("=", 1)
        try:
            svc_port_map[svc.strip().lower()] = int(port_str.strip())
        except ValueError:
            console.print(f"[failure]Error: Invalid port number in '{override}'[/failure]")
            sys.exit(1)

    # --- Parse targets ---
    targets = []
    for t in target_str:
        targets.append(parse_target(t))

    if targets_file:
        try:
            targets.extend(parse_targets_file(targets_file))
        except FileNotFoundError as e:
            console.print(f"[failure]Error: {e}[/failure]")
            sys.exit(1)

    if nmap_xml:
        try:
            targets.extend(parse_nmap_xml(nmap_xml))
        except FileNotFoundError as e:
            console.print(f"[failure]Error: {e}[/failure]")
            sys.exit(1)
        except Exception as e:
            console.print(f"[failure]Error parsing nmap XML: {e}[/failure]")
            sys.exit(1)

    if not targets:
        console.print("[failure]Error: No targets specified. Use -t, -T, or -n.[/failure]")
        sys.exit(1)

    # --- Nmap scan ---
    if not no_scan:
        from core.input_parser import run_nmap_scan
        from core.output import print_scan_results

        scan_hosts = list(set(t.host for t in targets))
        console.print(f"\n  [label]Running nmap scan on {len(scan_hosts)} host(s)...[/label]")
        scanned_targets = run_nmap_scan(scan_hosts, timeout=timeout * 60)

        if scanned_targets:
            print_scan_results(scanned_targets)
            # Report hosts with no open ports
            result_hosts = set(t.host for t in scanned_targets)
            missing = [h for h in scan_hosts if h not in result_hosts]
            for h in missing:
                console.print(f"  [dim]{h}: no open ports found[/dim]")
            # Replace targets with scan results (they have proper port/service info)
            targets = scanned_targets
        else:
            console.print("  [warn]Nmap scan returned no results. Continuing with original targets.[/warn]")

    # --- Auto-detect service from port for targets missing a service ---
    from core.input_parser import PORT_SERVICE_MAP

    for i, t in enumerate(targets):
        if t.port and not t.service:
            detected = PORT_SERVICE_MAP.get(t.port)
            if detected:
                targets[i] = Target(host=t.host, port=t.port, service=detected)
            else:
                console.print(
                    f"  [warn]Warning: Unknown service on {t.host}:{t.port} "
                    f"— use -s or host:port:service syntax[/warn]"
                )

    # --- Auto domain discovery (per-host, only on hosts with SMB/LDAP) ---
    host_domains = {}
    if not no_auto_domain and not domain:
        from modules.nxc_base import discover_domain

        # Only run nxc smb domain discovery on hosts that have SMB/LDAP ports open
        smb_hosts = set(
            t.host for t in targets
            if t.port in (139, 445, 389, 636) or t.service in ("smb", "ldap")
        )
        unique_hosts = [h for h in dict.fromkeys(t.host for t in targets) if h in smb_hosts]
        for host in unique_hosts:
            console.print(f"  [label]Discovering domain via nxc smb {host}...[/label]")
            discovered = discover_domain(host, timeout=timeout)
            if discovered:
                host_domains[host] = discovered
                console.print(f"  [success]{host} -> {discovered}[/success]")
            else:
                console.print(f"  [dim]{host} -> no domain[/dim]")
    elif domain:
        # Manual -d flag: apply to all hosts
        for t in targets:
            host_domains[t.host] = domain

    # --- Parse credentials ---
    try:
        credentials = parse_credentials(
            user=user,
            password=password,
            userfile=userfile,
            passfile=passfile,
            credsfile=credsfile,
        )
    except FileNotFoundError as e:
        console.print(f"[failure]Error: {e}[/failure]")
        sys.exit(1)

    if not credentials:
        console.print("[failure]Error: No credentials specified. Use -u/-p, -U/-P, or -C.[/failure]")
        sys.exit(1)

    # --- Select modules ---
    all_modules = ModuleRegistry.get_all()
    ModuleRegistry.print_skipped(console)

    if not all_modules:
        console.print("[failure]Error: No service modules found.[/failure]")
        sys.exit(1)

    if services:
        selected = {}
        for svc_name in services.split(","):
            svc_name = svc_name.strip().lower()
            if svc_name in all_modules:
                selected[svc_name] = all_modules[svc_name]
            else:
                console.print(f"[warn]Warning: Unknown service '{svc_name}', skipping.[/warn]")
        if not selected:
            console.print("[failure]Error: No valid services selected.[/failure]")
            sys.exit(1)
        modules = selected
    else:
        # If nmap targets have services, only load those modules
        nmap_services = {t.service for t in targets if t.service}
        if nmap_services:
            modules = {s: all_modules[s] for s in nmap_services if s in all_modules}
        else:
            # Default to library modules only (exclude nxc_ duplicates)
            # Use --nxc flag to swap to nxc modules instead
            modules = {k: v for k, v in all_modules.items() if not k.startswith("nxc_")}

    # --- NXC swap: replace library modules with nxc equivalents ---
    if nxc:
        NXC_MAP = {
            "smb": "nxc_smb",
            "evil-winrm": "nxc_winrm",
            "ssh": "nxc_ssh",
            "ldap": "nxc_ldap",
            "mssql": "nxc_mssql",
            "ftp": "nxc_ftp",
            "rdp": "nxc_rdp",
            "wmi": "nxc_wmi",
        }
        swapped = {}
        for name, mod_cls in modules.items():
            nxc_name = NXC_MAP.get(name)
            if nxc_name and nxc_name in all_modules:
                swapped[nxc_name] = all_modules[nxc_name]
            else:
                swapped[name] = mod_cls
        # Also add nxc-only modules (wmi, vnc) if no specific services were requested
        if not services:
            for extra in ("nxc_wmi", "nxc_vnc"):
                if extra in all_modules:
                    swapped[extra] = all_modules[extra]
        modules = swapped

        # Also swap service names on nmap-detected targets
        for i, t in enumerate(targets):
            if t.service and t.service in NXC_MAP:
                nxc_svc = NXC_MAP[t.service]
                if nxc_svc in modules:
                    targets[i] = Target(host=t.host, port=t.port, service=nxc_svc)

    # --- Warn about nmap-detected services with no matching module ---
    skipped_services = {}
    for t in targets:
        if t.service and t.service not in modules:
            key = t.service
            skipped_services.setdefault(key, []).append(f"{t.host}:{t.port}")
    if skipped_services:
        for svc, hosts in skipped_services.items():
            console.print(f"  [warn]No module for '{svc}' — skipping {', '.join(hosts)}[/warn]")

    # --- Deduplicate targets: same host+service+port, keep preferred for SMB ---
    # HTTP is exempt: different ports likely mean different web apps
    PREFERRED_PORTS = {"smb": 445}
    DEDUP_EXEMPT = {"http"}  # services where different ports should NOT be collapsed
    seen = {}
    deduped = []
    for t in targets:
        if not t.service or t.service not in modules:
            continue
        if t.service in DEDUP_EXEMPT:
            # Keep all ports for exempt services (each port = different app)
            port_key = (t.host, t.service, t.port)
            if port_key not in seen:
                seen[port_key] = len(deduped)
                deduped.append(t)
            continue
        key = (t.host, t.service)
        if key in seen:
            preferred = PREFERRED_PORTS.get(t.service)
            if preferred and t.port == preferred:
                deduped[seen[key]] = t
            continue
        seen[key] = len(deduped)
        deduped.append(t)
    targets = deduped

    # Display what we're doing
    console.print(f"  [label]Targets:[/label]  [value]{len(targets)}[/value]")
    console.print(f"  [label]Creds:[/label]    [value]{len(credentials)}[/value]")

    # Smart services display: show count when >10 unless dry-run or debug
    svc_names = sorted(modules.keys())
    if len(svc_names) <= 10 or dry_run or debug:
        console.print(f"  [label]Services:[/label] [value]{', '.join(svc_names)}[/value]")
    else:
        nxc_count = sum(1 for s in svc_names if s.startswith("nxc_"))
        lib_count = len(svc_names) - nxc_count
        console.print(
            f"  [label]Services:[/label] [value]{len(svc_names)} "
            f"({lib_count} library, {nxc_count} nxc)[/value] "
            f"[dim]Use --dry-run to see full list[/dim]"
        )

    console.print(f"  [label]Threads:[/label]  [value]{threads}[/value]")
    if host_domains:
        unique_domains = sorted(set(host_domains.values()))
        console.print(f"  [label]Domain:[/label]   [value]{', '.join(unique_domains)}[/value]")
    if svc_port_map:
        overrides_str = ", ".join(f"{s}={p}" for s, p in svc_port_map.items())
        console.print(f"  [label]Ports:[/label]    [value]{overrides_str}[/value]")

    # --- Build extra kwargs ---
    extra_kwargs = {}
    if url_path != "/":
        extra_kwargs["url_path"] = url_path
    if http_form_data:
        extra_kwargs["http_form_data"] = http_form_data
    if success_string:
        extra_kwargs["success_string"] = success_string

    # --- Dry run: show plan and exit ---
    if dry_run:
        from core.output import print_dry_run
        print_dry_run(targets, credentials, modules, svc_port_map, mask_creds=mask_creds)
        return

    # --- Run the spray ---
    engine = SprayEngine(
        threads=threads,
        timeout=timeout,
        delay=delay,
        extra_kwargs=extra_kwargs,
        port_overrides=svc_port_map,
        host_domains=host_domains,
        verify=verify,
        debug=debug,
        mask_creds=mask_creds,
    )

    try:
        results = engine.spray(targets, credentials, modules)
    except KeyboardInterrupt:
        console.print("\n[warn]Interrupted by user.[/warn]")
        results = []

    # --- Output results ---
    if results:
        print_results_table(results, show_all=show_all, elapsed=getattr(engine, 'elapsed', None), mask_creds=mask_creds)
    else:
        console.print("[dim]No results collected.[/dim]")

    # --- Write JSON output if requested ---
    if output_file:
        from core.output import write_json_output
        elapsed = getattr(engine, 'elapsed', None)
        write_json_output(output_file, results, elapsed=elapsed, mask_creds=mask_creds)


if __name__ == "__main__":
    main()
