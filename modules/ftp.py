"""FTP service module using ftplib (stdlib)."""

import ftplib
import socket
from typing import Optional

from core.models import Credential, Target
from modules.base import ServiceModule


class FTPModule(ServiceModule):
    name = "ftp"
    default_port = 21
    alternate_ports = [2121]

    def test_credential(self, target: Target, credential: Credential, timeout: int = 5, **kwargs) -> bool:
        port = target.port or self.default_port
        ftp = ftplib.FTP()
        try:
            ftp.connect(host=target.host, port=port, timeout=timeout)
            ftp.login(user=credential.username, passwd=credential.password)
            return True
        except ftplib.error_perm as e:
            if "530" in str(e):  # Login incorrect
                return False
            raise
        except socket.timeout:
            raise TimeoutError(f"FTP connection to {target.host}:{port} timed out")
        finally:
            try:
                ftp.quit()
            except Exception:
                pass

    def verify_access(self, target: Target, credential: Credential, timeout: int = 5, **kwargs) -> Optional[str]:
        port = target.port or self.default_port
        ftp = ftplib.FTP()
        try:
            ftp.connect(host=target.host, port=port, timeout=timeout)
            ftp.login(user=credential.username, passwd=credential.password)
            pwd = ftp.pwd()
            listing = []
            ftp.retrlines("LIST", listing.append)
            ftp.quit()
            items = len(listing)
            return f"CWD={pwd} ({items} items)"
        except Exception:
            return None
