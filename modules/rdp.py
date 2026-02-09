"""RDP service module using xfreerdp +auth-only with nxc fallback."""

import shutil
import subprocess
from typing import Optional

from core.models import Credential, Target
from modules.base import ServiceModule


class RDPModule(ServiceModule):
    name = "rdp"
    default_port = 3389
    alternate_ports = []

    def test_credential(self, target: Target, credential: Credential, timeout: int = 5, **kwargs) -> bool:
        port = target.port or self.default_port

        # Primary: xfreerdp +auth-only (most reliable RDP auth check)
        binary = shutil.which("xfreerdp3") or shutil.which("xfreerdp")
        if binary:
            try:
                return self._try_xfreerdp(target.host, port, credential, timeout, binary=binary)
            except TimeoutError:
                raise
            except Exception:
                pass

        # Fallback: nxc rdp
        if shutil.which("nxc"):
            try:
                return self._try_nxc(target.host, port, credential, timeout, **kwargs)
            except TimeoutError:
                raise
            except Exception:
                pass

        # Last resort: impacket CredSSP
        try:
            return self._try_impacket(target.host, port, credential, timeout, **kwargs)
        except Exception:
            pass

        return False

    def _try_xfreerdp(self, host: str, port: int, credential: Credential, timeout: int, binary: str = "xfreerdp") -> bool:
        cmd = [
            binary,
            f"/v:{host}:{port}",
            f"/u:{credential.username}",
            "+auth-only",
            "/cert:ignore",
            f"/timeout:{timeout * 1000}",
        ]
        if credential.is_hash:
            cmd.append(f"/pth:{credential.nthash}")
        else:
            cmd.append(f"/p:{credential.password}")

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout + 10
            )
            # xfreerdp returns 0 on successful auth with +auth-only
            if result.returncode == 0:
                return True
            # Check for auth failure indicators
            stderr = result.stderr.lower()
            if "logon_failure" in stderr or "authentication" in stderr:
                return False
            return False
        except subprocess.TimeoutExpired:
            raise TimeoutError(f"RDP connection to {host}:{port} timed out")

    def _try_nxc(self, host: str, port: int, credential: Credential, timeout: int, **kwargs) -> bool:
        """Use nxc rdp for auth checking."""
        cmd = ["nxc", "rdp", host, "--port", str(port), "-u", credential.username]
        if credential.is_hash:
            cmd += ["-H", credential.nthash]
        else:
            cmd += ["-p", credential.password]

        domain = kwargs.get("domain")
        if domain:
            cmd += ["-d", domain]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 15)
        except subprocess.TimeoutExpired:
            raise TimeoutError(f"nxc rdp {host}:{port} timed out")

        for line in result.stdout.splitlines():
            if "(Guest)" in line:
                return False
            if "[+]" in line:
                return True
            if "[-]" in line:
                return False
        return False

    def _try_impacket(self, host: str, port: int, credential: Credential, timeout: int, **kwargs) -> bool:
        from impacket.dcerpc.v5 import transport

        domain = kwargs.get("domain", "")
        string_binding = f"ncacn_np:{host}[\\pipe\\browser]"
        rpc_transport = transport.DCERPCTransportFactory(string_binding)
        rpc_transport.set_connect_timeout(timeout)
        if credential.is_hash:
            rpc_transport.set_credentials(
                credential.username, "", domain,
                "", credential.nthash
            )
        else:
            rpc_transport.set_credentials(
                credential.username, credential.password, domain, "", ""
            )
        rpc_transport.set_dport(port)

        try:
            dce = rpc_transport.get_dce_rpc()
            dce.connect()
            dce.disconnect()
            return True
        except Exception as e:
            err = str(e).lower()
            if "logon_failure" in err or "access_denied" in err:
                return False
            raise

    def verify_access(self, target: Target, credential: Credential, timeout: int = 5, **kwargs) -> Optional[str]:
        port = target.port or self.default_port
        # Report which method succeeded
        binary = shutil.which("xfreerdp3") or shutil.which("xfreerdp")
        if binary:
            try:
                if self._try_xfreerdp(target.host, port, credential, timeout, binary=binary):
                    return f"RDP auth OK via xfreerdp ({target.host}:{port})"
            except Exception:
                pass
        if shutil.which("nxc"):
            try:
                if self._try_nxc(target.host, port, credential, timeout, **kwargs):
                    return f"RDP auth OK via nxc ({target.host}:{port})"
            except Exception:
                pass
        try:
            if self._try_impacket(target.host, port, credential, timeout, **kwargs):
                return f"RDP auth OK via CredSSP ({target.host}:{port})"
        except Exception:
            pass
        return None
