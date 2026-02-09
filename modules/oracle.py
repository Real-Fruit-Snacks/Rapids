"""Oracle DB service module using oracledb (thin mode, no Oracle client needed)."""

from typing import Optional

import oracledb

from core.models import Credential, Target
from modules.base import ServiceModule


class OracleModule(ServiceModule):
    name = "oracle"
    default_port = 1521
    alternate_ports = [1522]

    def test_credential(self, target: Target, credential: Credential, timeout: int = 5, **kwargs) -> bool:
        port = target.port or self.default_port
        # Default SID/service name
        sid = kwargs.get("oracle_sid", "ORCL")

        dsn = f"{target.host}:{port}/{sid}"
        try:
            conn = oracledb.connect(
                user=credential.username,
                password=credential.password,
                dsn=dsn,
                tcp_connect_timeout=timeout,
            )
            conn.close()
            return True
        except oracledb.DatabaseError as e:
            err_obj = e.args[0] if e.args else None
            err_str = str(e).lower()
            # ORA-01017: invalid username/password
            if "ora-01017" in err_str:
                return False
            # ORA-28000: account is locked
            if "ora-28000" in err_str:
                return False
            if "connection refused" in err_str or "[errno 111]" in err_str:
                raise ConnectionRefusedError(f"Oracle connection to {target.host}:{port} refused")
            if "timed out" in err_str or "timeout" in err_str:
                raise TimeoutError(str(e))
            raise

    def verify_access(self, target: Target, credential: Credential, timeout: int = 5, **kwargs) -> Optional[str]:
        port = target.port or self.default_port
        sid = kwargs.get("oracle_sid", "ORCL")
        dsn = f"{target.host}:{port}/{sid}"
        try:
            conn = oracledb.connect(
                user=credential.username, password=credential.password,
                dsn=dsn, tcp_connect_timeout=timeout,
            )
            cursor = conn.cursor()
            cursor.execute(
                "SELECT user, ora_database_name, banner FROM v$version WHERE ROWNUM = 1"
            )
            row = cursor.fetchone()
            cursor.close()
            conn.close()
            if row:
                return f"user={row[0]} db={row[1]} {row[2]}"
            return "Authenticated"
        except Exception:
            return None
