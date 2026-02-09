"""SMB service module using impacket."""

from typing import Optional

from impacket.smbconnection import SMBConnection

from core.models import Credential, Target
from modules.base import ServiceModule


class SMBModule(ServiceModule):
    name = "smb"
    default_port = 445
    alternate_ports = [139]

    def test_credential(self, target: Target, credential: Credential, timeout: int = 5, **kwargs) -> bool:
        port = target.port or self.default_port
        domain = kwargs.get("domain", "")
        try:
            conn = SMBConnection(target.host, target.host, sess_port=port, timeout=timeout)
            if credential.is_hash:
                conn.login(credential.username, "", domain=domain, nthash=credential.nthash)
            else:
                conn.login(credential.username, credential.password, domain=domain)
            # Reject Guest logins
            if conn.isGuestSession():
                conn.logoff()
                return False
            conn.logoff()
            return True
        except Exception as e:
            err = str(e).lower()
            if "logon_failure" in err or "status_logon_failure" in err or "bad_password" in err:
                return False
            if "timed out" in err or "timeout" in err:
                raise TimeoutError(str(e))
            raise

    def verify_access(self, target: Target, credential: Credential, timeout: int = 5, **kwargs) -> Optional[str]:
        port = target.port or self.default_port
        domain = kwargs.get("domain", "")
        conn = SMBConnection(target.host, target.host, sess_port=port, timeout=timeout)
        if credential.is_hash:
            conn.login(credential.username, "", domain=domain, nthash=credential.nthash)
        else:
            conn.login(credential.username, credential.password, domain=domain)
        shares = conn.listShares()
        share_names = [s["shi1_netname"][:-1] for s in shares]
        conn.logoff()
        return "Shares: " + ", ".join(share_names)
