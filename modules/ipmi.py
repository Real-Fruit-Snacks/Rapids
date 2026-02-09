"""IPMI service module using ipmitool CLI."""

import shutil
import subprocess
from typing import Optional

from core.models import Credential, Target
from modules.base import ServiceModule


class IPMIModule(ServiceModule):
    name = "ipmi"
    default_port = 623
    alternate_ports = []

    def test_credential(self, target: Target, credential: Credential, timeout: int = 5, **kwargs) -> bool:
        if not shutil.which("ipmitool"):
            raise RuntimeError(
                "ipmitool not found in PATH. "
                "Install with: apt install ipmitool"
            )

        cmd = [
            "ipmitool",
            "-I", "lanplus",
            "-H", target.host,
            "-U", credential.username,
            "-P", credential.password,
            "chassis", "status",
        ]

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout + 10
            )
        except subprocess.TimeoutExpired:
            raise TimeoutError(f"IPMI connection to {target.host} timed out")

        out = result.stdout + result.stderr
        if result.returncode == 0 and ("System Power" in out or "Chassis Power" in out):
            return True
        if "Unable to establish" in out or "RAKP" in out or "password" in out.lower():
            return False
        return False

    def verify_access(self, target: Target, credential: Credential, timeout: int = 5, **kwargs) -> Optional[str]:
        if not shutil.which("ipmitool"):
            return None

        cmd = [
            "ipmitool",
            "-I", "lanplus",
            "-H", target.host,
            "-U", credential.username,
            "-P", credential.password,
            "chassis", "status",
        ]

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout + 10
            )
        except subprocess.TimeoutExpired:
            return None

        if result.returncode == 0:
            for line in result.stdout.splitlines():
                if "System Power" in line or "Chassis Power" in line:
                    return line.strip()
            return "IPMI access confirmed"
        return None
