"""Input parsing for targets, credentials, and nmap XML."""

import shutil
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List, Tuple

from core.models import Credential, Target


def is_nthash(value: str) -> bool:
    """Check if a string is an NT hash (32 hex chars, optionally prefixed with ':')."""
    clean = value.lstrip(':')
    if len(clean) == 32:
        try:
            int(clean, 16)
            return True
        except ValueError:
            pass
    return False


# Map common ports to service module names
PORT_SERVICE_MAP = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    80: "http",
    88: "kerberos",
    110: "pop3",
    135: "wmi",
    139: "smb",
    143: "imap",
    161: "snmp",
    389: "ldap",
    443: "http",
    445: "smb",
    465: "smtp",
    587: "smtp",
    993: "imap",
    995: "pop3",
    1433: "mssql",
    1521: "oracle",
    1883: "mqtt",
    3306: "mysql",
    3389: "rdp",
    3306: "mysql",
    3389: "rdp",
    5432: "postgres",
    5900: "vnc",
    5984: "couchdb",
    5985: "evil-winrm",
    5986: "evil-winrm",
    6379: "redis",
    8080: "http",
    8443: "http",
    8883: "mqtt",
    9042: "cassandra",
    9200: "elasticsearch",
    11211: "memcached",
    27017: "mongodb",
}

# Map nmap service names to module names
NMAP_SERVICE_MAP = {
    "ssh": "ssh",
    "ftp": "ftp",
    "telnet": "telnet",
    "smtp": "smtp",
    "pop3": "pop3",
    "pop3s": "pop3",
    "imap": "imap",
    "imaps": "imap",
    "snmp": "snmp",
    "microsoft-ds": "smb",
    "netbios-ssn": "smb",
    "ms-sql-s": "mssql",
    "mysql": "mysql",
    "postgresql": "postgres",
    "oracle-tns": "oracle",
    "http": "http",
    "https": "http",
    "http-proxy": "http",
    "ms-wbt-server": "rdp",
    "vnc": "vnc",
    "vnc-http": "vnc",
    "redis": "redis",
    "mongodb": "mongodb",
    "mongod": "mongodb",
    "ldap": "ldap",
    "kerberos-sec": "kerberos",
    "kerberos": "kerberos",
    "mysql": "mysql",
    "redis": "redis",
    "ipmi": "ipmi",
    "winrm": "evil-winrm",
    "wsman": "evil-winrm",
    "msrpc": "wmi",
    "epmap": "wmi",
    "mqtt": "mqtt",
    "couchdb": "couchdb",
    "elasticsearch": "elasticsearch",
    "memcached": "memcached",
    "cassandra": "cassandra",
}


def parse_target(target_str: str) -> Target:
    """Parse a target string like 'host', 'host:port', or 'host:port:service'."""
    parts = target_str.strip().split(":")
    host = parts[0]
    port = int(parts[1]) if len(parts) > 1 else None
    service = parts[2] if len(parts) > 2 else None
    return Target(host=host, port=port, service=service)


def parse_targets_file(filepath: str) -> List[Target]:
    """Parse a file with one target per line."""
    targets = []
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"Targets file not found: {filepath}")

    for line in path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            targets.append(parse_target(line))
    return targets


def parse_nmap_xml(filepath: str) -> List[Target]:
    """Parse nmap XML output and create targets with service detection."""
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"Nmap XML file not found: {filepath}")

    tree = ET.parse(str(path))
    root = tree.getroot()
    targets = []

    for host in root.findall(".//host"):
        # Get the host address
        addr_elem = host.find("address[@addrtype='ipv4']")
        if addr_elem is None:
            addr_elem = host.find("address")
        if addr_elem is None:
            continue
        host_addr = addr_elem.get("addr", "")

        # Get open ports
        for port_elem in host.findall(".//port"):
            state_elem = port_elem.find("state")
            if state_elem is None or state_elem.get("state") != "open":
                continue

            port_num = int(port_elem.get("portid", "0"))
            protocol = port_elem.get("protocol", "tcp")
            if protocol != "tcp":
                continue

            # Determine service name and extract version info
            service_name = None
            nmap_name = ""
            nmap_product = ""
            nmap_version = ""
            svc_elem = port_elem.find("service")
            if svc_elem is not None:
                nmap_name = svc_elem.get("name", "")
                nmap_product = svc_elem.get("product", "")
                nmap_version = svc_elem.get("version", "")
                service_name = NMAP_SERVICE_MAP.get(nmap_name)

            # If nmap says "http" but port maps to a more specific service, prefer that
            if service_name == "http" and port_num in PORT_SERVICE_MAP:
                specific = PORT_SERVICE_MAP[port_num]
                if specific != "http":
                    service_name = specific

            # Fallback to port-based mapping
            if not service_name:
                service_name = PORT_SERVICE_MAP.get(port_num)

            if service_name:
                targets.append(Target(
                    host=host_addr,
                    port=port_num,
                    service=service_name,
                    nmap_service=nmap_name or None,
                    nmap_product=nmap_product or None,
                    nmap_version=nmap_version or None,
                ))

    return targets


def run_nmap_scan(hosts: List[str], timeout: int = 300) -> List[Target]:
    """Run nmap TCP connect scan with service detection and return discovered targets."""
    if not shutil.which("nmap"):
        from rich.console import Console
        from core.theme import RAPIDS_THEME
        Console(theme=RAPIDS_THEME).print("[failure]Error: nmap not found in PATH. Install with: apt install nmap[/failure]")
        return []

    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
    from core.theme import RAPIDS_THEME, MOCHA

    console = Console(theme=RAPIDS_THEME)
    cmd = ["nmap", "-sT", "-sV", "--open", "-oX", "-"] + hosts

    host_label = hosts[0] if len(hosts) == 1 else f"{len(hosts)} hosts"

    with Progress(
        SpinnerColumn(style=MOCHA["mauve"]),
        TextColumn(f"[{MOCHA['blue']}]" + "{task.description}" + f"[/{MOCHA['blue']}]"),
        BarColumn(complete_style=MOCHA["green"], finished_style=MOCHA["green"], pulse_style=MOCHA["mauve"]),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        progress.add_task(f"Scanning {host_label}...", total=None)

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                stdout, stderr = proc.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.communicate()
                console.print(f"[warn]Nmap scan timed out after {timeout}s[/warn]")
                return []
        except OSError as e:
            console.print(f"[failure]Failed to run nmap: {e}[/failure]")
            return []

    if proc.returncode != 0 and not stdout:
        console.print(f"[failure]Nmap error: {stderr.strip()}[/failure]")
        return []

    # Parse the XML output (reuse same logic as parse_nmap_xml)
    targets = []
    try:
        root = ET.fromstring(stdout)
    except ET.ParseError:
        return []

    for host in root.findall(".//host"):
        addr_elem = host.find("address[@addrtype='ipv4']")
        if addr_elem is None:
            addr_elem = host.find("address")
        if addr_elem is None:
            continue
        host_addr = addr_elem.get("addr", "")

        for port_elem in host.findall(".//port"):
            state_elem = port_elem.find("state")
            if state_elem is None or state_elem.get("state") != "open":
                continue

            port_num = int(port_elem.get("portid", "0"))
            protocol = port_elem.get("protocol", "tcp")
            if protocol != "tcp":
                continue

            service_name = None
            nmap_name = ""
            nmap_product = ""
            nmap_version = ""
            svc_elem = port_elem.find("service")
            if svc_elem is not None:
                nmap_name = svc_elem.get("name", "")
                nmap_product = svc_elem.get("product", "")
                nmap_version = svc_elem.get("version", "")
                service_name = NMAP_SERVICE_MAP.get(nmap_name)

            # If nmap says "http" but port maps to a more specific service, prefer that
            if service_name == "http" and port_num in PORT_SERVICE_MAP:
                specific = PORT_SERVICE_MAP[port_num]
                if specific != "http":
                    service_name = specific

            if not service_name:
                service_name = PORT_SERVICE_MAP.get(port_num)

            if service_name:
                targets.append(Target(
                    host=host_addr, port=port_num, service=service_name,
                    nmap_service=nmap_name or None,
                    nmap_product=nmap_product or None,
                    nmap_version=nmap_version or None,
                ))

    return targets


def parse_credentials(
    user: str = None,
    password: str = None,
    userfile: str = None,
    passfile: str = None,
    credsfile: str = None,
) -> List[Credential]:
    """Build credential list from CLI arguments."""
    creds = []

    # Single user:pass pair
    if user and password:
        if is_nthash(password):
            creds.append(Credential(username=user, password="", nthash=password.lstrip(':')))
        else:
            creds.append(Credential(username=user, password=password))

    # Cartesian product of user file x password file
    users = []
    passwords = []

    if userfile:
        path = Path(userfile)
        if not path.exists():
            raise FileNotFoundError(f"User file not found: {userfile}")
        users = [
            l.strip() for l in path.read_text().splitlines()
            if l.strip() and not l.startswith("#")
        ]

    if passfile:
        path = Path(passfile)
        if not path.exists():
            raise FileNotFoundError(f"Password file not found: {passfile}")
        passwords = [
            l.strip() for l in path.read_text().splitlines()
            if l.strip() and not l.startswith("#")
        ]

    # Single user with password file
    if user and not userfile:
        users = [user]
    # Single password with user file
    if password and not passfile:
        passwords = [password]

    # Build cartesian product
    if users and passwords:
        for u in users:
            for p in passwords:
                if is_nthash(p):
                    c = Credential(username=u, password="", nthash=p.lstrip(':'))
                else:
                    c = Credential(username=u, password=p)
                if c not in creds:
                    creds.append(c)

    # Colon-separated creds file (user:pass per line)
    if credsfile:
        path = Path(credsfile)
        if not path.exists():
            raise FileNotFoundError(f"Creds file not found: {credsfile}")
        for line in path.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and ":" in line:
                parts = line.split(":", 1)
                cred_value = parts[1]
                if is_nthash(cred_value):
                    c = Credential(username=parts[0], password="", nthash=cred_value.lstrip(':'))
                else:
                    c = Credential(username=parts[0], password=cred_value)
                if c not in creds:
                    creds.append(c)

    return creds
