"""MySQL service module using pymysql."""

from typing import Optional

import pymysql

from core.models import Credential, Target
from modules.base import ServiceModule


class MySQLModule(ServiceModule):
    name = "mysql"
    default_port = 3306
    alternate_ports = [3307]

    def test_credential(self, target: Target, credential: Credential, timeout: int = 5, **kwargs) -> bool:
        port = target.port or self.default_port
        try:
            conn = pymysql.connect(
                host=target.host,
                port=port,
                user=credential.username,
                password=credential.password,
                connect_timeout=timeout,
                read_timeout=timeout,
            )
            conn.close()
            return True
        except pymysql.err.OperationalError as e:
            err_code = e.args[0] if e.args else 0
            err_msg = str(e).lower()
            # 1045 = Access denied
            if err_code == 1045 or "access denied" in err_msg:
                return False
            if "connection refused" in err_msg or "[errno 111]" in err_msg:
                raise ConnectionRefusedError(f"MySQL connection to {target.host}:{port} refused")
            if "timed out" in err_msg or "timeout" in err_msg:
                raise TimeoutError(str(e))
            raise

    def verify_access(self, target: Target, credential: Credential, timeout: int = 5, **kwargs) -> Optional[str]:
        port = target.port or self.default_port
        try:
            conn = pymysql.connect(
                host=target.host, port=port,
                user=credential.username,
                password=credential.password,
                connect_timeout=timeout,
            )
            cursor = conn.cursor()
            cursor.execute("SELECT user(), version(), @@hostname")
            row = cursor.fetchone()
            conn.close()
            return f"user={row[0]} version={row[1]} host={row[2]}"
        except Exception:
            return None
