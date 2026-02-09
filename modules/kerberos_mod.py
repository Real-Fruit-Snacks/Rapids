"""Kerberos service module using impacket getTGT."""

import shutil
import subprocess
from typing import Optional

from core.models import Credential, Target
from modules.base import ServiceModule


class KerberosModule(ServiceModule):
    name = "kerberos"
    default_port = 88
    alternate_ports = []

    def test_credential(self, target: Target, credential: Credential, timeout: int = 5, **kwargs) -> bool:
        domain = kwargs.get("domain", "")
        if not domain:
            raise RuntimeError(
                "Kerberos requires a domain (use -d/--domain)"
            )

        # Try impacket library first
        try:
            return self._try_impacket_lib(target.host, credential, domain, timeout)
        except ImportError:
            pass

        # Fallback to impacket CLI
        gettgt = shutil.which("impacket-getTGT") or shutil.which("getTGT.py")
        if gettgt:
            return self._try_impacket_cli(gettgt, target.host, credential, domain, timeout)

        raise RuntimeError(
            "Kerberos auth requires impacket. "
            "Install with: pip install impacket"
        )

    def _try_impacket_lib(self, dc_ip: str, credential: Credential, domain: str, timeout: int) -> bool:
        from impacket.krb5.kerberosv5 import getKerberosTGT
        from impacket.krb5.types import Principal

        username = Principal(credential.username, type=1)

        try:
            if credential.is_hash:
                tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(
                    username, "", domain,
                    bytes.fromhex("0" * 32),  # empty LM hash
                    bytes.fromhex(credential.nthash),
                    None, dc_ip,
                )
            else:
                tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(
                    username, credential.password, domain,
                    None, None, None, dc_ip,
                )
            return True
        except Exception as e:
            err = str(e)
            if "KDC_ERR_PREAUTH_FAILED" in err:
                return False
            if "KDC_ERR_C_PRINCIPAL_UNKNOWN" in err:
                return False
            if "KDC_ERR_CLIENT_REVOKED" in err:
                return False
            if "timed out" in err.lower() or "timeout" in err.lower():
                raise TimeoutError(str(e))
            raise

    def _try_impacket_cli(self, binary: str, dc_ip: str, credential: Credential, domain: str, timeout: int) -> bool:
        if credential.is_hash:
            cmd = [
                binary,
                "-hashes", f":{credential.nthash}",
                f"{domain}/{credential.username}",
                "-dc-ip", dc_ip,
            ]
        else:
            cmd = [
                binary,
                f"{domain}/{credential.username}:{credential.password}",
                "-dc-ip", dc_ip,
            ]

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout + 10
            )
        except subprocess.TimeoutExpired:
            raise TimeoutError(f"Kerberos getTGT to {dc_ip} timed out")

        out = result.stdout + result.stderr
        if "Saving ticket" in out:
            return True
        if "KDC_ERR_PREAUTH_FAILED" in out:
            return False
        if "KDC_ERR_C_PRINCIPAL_UNKNOWN" in out:
            return False
        if "KDC_ERR_CLIENT_REVOKED" in out:
            return False
        return False

    def verify_access(self, target: Target, credential: Credential, timeout: int = 5, **kwargs) -> Optional[str]:
        domain = kwargs.get("domain", "")
        if not domain:
            return None
        try:
            if self.test_credential(target, credential, timeout, **kwargs):
                return f"TGT obtained for {credential.username}@{domain}"
        except Exception:
            pass
        return None
