"""Base class for NetExec (nxc) backed service modules."""

import re
import shutil
import subprocess
from typing import Optional

from core.models import Credential, Target
from modules.base import ServiceModule


class NxcModule(ServiceModule):
    """Base class for modules that shell out to nxc."""

    nxc_protocol: str = ""

    def test_credential(
        self,
        target: Target,
        credential: Credential,
        timeout: int = 5,
        **kwargs,
    ) -> bool:
        if not shutil.which("nxc"):
            raise RuntimeError(
                "NetExec (nxc) not found in PATH. "
                "Install with: apt install netexec / pipx install netexec"
            )

        cmd = ["nxc", self.nxc_protocol, target.host]

        port = target.port or self.default_port
        if target.port:
            cmd += ["--port", str(port)]

        cmd += ["-u", credential.username]
        if credential.is_hash:
            cmd += ["-H", credential.nthash]
        else:
            cmd += ["-p", credential.password]

        domain = kwargs.get("domain")
        if domain:
            cmd += ["-d", domain]

        # Protocol-specific flags
        extra = self._extra_args(**kwargs)
        if extra:
            cmd.extend(extra)

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout + 15,
            )
        except subprocess.TimeoutExpired:
            raise TimeoutError(
                f"nxc {self.nxc_protocol} {target.host}:{port} timed out"
            )

        stdout = result.stdout
        for line in stdout.splitlines():
            # Reject Guest logins as not real authentication
            if "(Guest)" in line:
                return False
            if "[+]" in line:
                return True
            if "[-]" in line:
                return False

        # If no clear indicator, treat as error
        stderr = result.stderr.strip()
        if stderr:
            raise RuntimeError(f"nxc error: {stderr}")
        return False

    def verify_access(
        self,
        target: Target,
        credential: Credential,
        timeout: int = 5,
        **kwargs,
    ) -> Optional[str]:
        """Re-run nxc and capture output details (Pwn3d!, shares, etc.)."""
        if not shutil.which("nxc"):
            return None

        cmd = ["nxc", self.nxc_protocol, target.host]
        port = target.port or self.default_port
        if target.port:
            cmd += ["--port", str(port)]
        cmd += ["-u", credential.username]
        if credential.is_hash:
            cmd += ["-H", credential.nthash]
        else:
            cmd += ["-p", credential.password]

        domain = kwargs.get("domain")
        if domain:
            cmd += ["-d", domain]

        extra = self._extra_args(**kwargs)
        if extra:
            cmd.extend(extra)

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 15)
        except subprocess.TimeoutExpired:
            return None

        for line in result.stdout.splitlines():
            # Reject Guest logins
            if "(Guest)" in line:
                return None
            if "[+]" in line:
                # Return everything after [+] as proof (includes Pwn3d!, domain info, etc.)
                proof = line.split("[+]", 1)[1].strip()
                return proof
        return None

    def _extra_args(self, **kwargs) -> list:
        """Override in subclasses to add protocol-specific nxc flags."""
        return []


def discover_domain(host: str, timeout: int = 5) -> Optional[str]:
    """Use nxc smb to discover the domain name from a target.

    Returns the domain string (e.g. 'CORP.LOCAL') or None.
    """
    if not shutil.which("nxc"):
        return None

    try:
        result = subprocess.run(
            ["nxc", "smb", host],
            capture_output=True,
            text=True,
            timeout=timeout + 10,
        )
    except subprocess.TimeoutExpired:
        return None

    for line in result.stdout.splitlines():
        # nxc outputs: (domain:CORP.LOCAL)
        match = re.search(r"\(domain:([^)]+)\)", line)
        if match:
            domain = match.group(1)
            if domain and domain != "":
                return domain
    return None
