"""MSSQL service module using impacket."""

from typing import Optional

from impacket.tds import MSSQL as MSSQLClient

from core.models import Credential, Target
from modules.base import ServiceModule


class MSSQLModule(ServiceModule):
    name = "mssql"
    default_port = 1433
    alternate_ports = [1434]

    def test_credential(self, target: Target, credential: Credential, timeout: int = 5, **kwargs) -> bool:
        port = target.port or self.default_port
        domain = kwargs.get("domain", "")
        try:
            client = MSSQLClient(target.host, port)
            client.connect()
            if credential.is_hash:
                result = client.login(
                    database="",
                    username=credential.username,
                    password="",
                    domain=domain or "",
                    nthash=credential.nthash,
                )
            elif domain:
                result = client.login(
                    database="",
                    username=credential.username,
                    password=credential.password,
                    domain=domain,
                )
            else:
                result = client.login(
                    database="",
                    username=credential.username,
                    password=credential.password,
                )
            client.disconnect()
            return bool(result)
        except Exception as e:
            err = str(e).lower()
            if "login failed" in err or "logon_failure" in err:
                return False
            if "timed out" in err or "timeout" in err:
                raise TimeoutError(str(e))
            raise

    def verify_access(self, target: Target, credential: Credential, timeout: int = 5, **kwargs) -> Optional[str]:
        port = target.port or self.default_port
        domain = kwargs.get("domain", "")
        client = MSSQLClient(target.host, port)
        client.connect()
        if credential.is_hash:
            client.login("", credential.username, "", domain or "", nthash=credential.nthash)
        elif domain:
            client.login("", credential.username, credential.password, domain)
        else:
            client.login("", credential.username, credential.password)
        client.sql_query("SELECT SYSTEM_USER AS [user], @@SERVERNAME AS [server], CASE WHEN IS_SRVROLEMEMBER('sysadmin')=1 THEN 'YES' ELSE 'NO' END AS [sysadmin]")
        rows = client.printRows()
        client.disconnect()
        return rows if rows else "Authenticated (query returned no rows)"
