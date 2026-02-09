"""WMI service module using nxc (no pure-library option)."""

import shutil
import subprocess
from typing import Optional

from core.models import Credential, Target
from modules.base import ServiceModule


class WMIModule(ServiceModule):
    name = "wmi"
    default_port = 135
    alternate_ports = []

    def test_credential(self, target: Target, credential: Credential, timeout: int = 5, **kwargs) -> bool:
        # WMI has no good pure-Python library; use nxc or impacket wmiexec
        if shutil.which("nxc"):
            return self._try_nxc(target, credential, timeout, **kwargs)

        raise RuntimeError(
            "WMI auth requires NetExec (nxc). "
            "Install with: apt install netexec / pipx install netexec"
        )

    def _try_nxc(self, target: Target, credential: Credential, timeout: int, **kwargs) -> bool:
        cmd = ["nxc", "wmi", target.host, "-u", credential.username]
        if credential.is_hash:
            cmd += ["-H", credential.nthash]
        else:
            cmd += ["-p", credential.password]

        domain = kwargs.get("domain")
        if domain:
            cmd += ["-d", domain]

        port = target.port or self.default_port
        if target.port:
            cmd += ["--port", str(port)]

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout + 15
            )
        except subprocess.TimeoutExpired:
            raise TimeoutError(f"nxc wmi {target.host}:{port} timed out")

        for line in result.stdout.splitlines():
            if "(Guest)" in line:
                return False
            if "[+]" in line:
                return True
            if "[-]" in line:
                return False
        return False

    def verify_access(self, target: Target, credential: Credential, timeout: int = 5, **kwargs) -> Optional[str]:
        if not shutil.which("nxc"):
            return None

        cmd = ["nxc", "wmi", target.host, "-u", credential.username]
        if credential.is_hash:
            cmd += ["-H", credential.nthash]
        else:
            cmd += ["-p", credential.password]

        domain = kwargs.get("domain")
        if domain:
            cmd += ["-d", domain]

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout + 15
            )
        except subprocess.TimeoutExpired:
            return None

        for line in result.stdout.splitlines():
            if "(Guest)" in line:
                return None
            if "[+]" in line:
                proof = line.split("[+]", 1)[1].strip()
                return proof
        return None
