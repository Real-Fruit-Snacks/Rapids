"""PostgreSQL service module using psycopg2."""

from typing import Optional

import psycopg2

from core.models import Credential, Target
from modules.base import ServiceModule


class PostgresModule(ServiceModule):
    name = "postgres"
    default_port = 5432
    alternate_ports = [5433]

    def test_credential(self, target: Target, credential: Credential, timeout: int = 5, **kwargs) -> bool:
        port = target.port or self.default_port
        try:
            conn = psycopg2.connect(
                host=target.host,
                port=port,
                user=credential.username,
                password=credential.password,
                connect_timeout=timeout,
                dbname="postgres",
            )
            conn.close()
            return True
        except psycopg2.OperationalError as e:
            err = str(e).lower()
            if "password authentication failed" in err or "no pg_hba.conf" in err:
                return False
            if "connection refused" in err or "[errno 111]" in err:
                raise ConnectionRefusedError(f"PostgreSQL connection to {target.host}:{port} refused")
            if "timed out" in err or "timeout" in err:
                raise TimeoutError(str(e))
            raise

    def verify_access(self, target: Target, credential: Credential, timeout: int = 5, **kwargs) -> Optional[str]:
        port = target.port or self.default_port
        conn = psycopg2.connect(
            host=target.host, port=port,
            user=credential.username, password=credential.password,
            connect_timeout=timeout, dbname="postgres",
        )
        cursor = conn.cursor()
        cursor.execute("SELECT current_user, version(), inet_server_addr()")
        row = cursor.fetchone()
        conn.close()
        return f"user={row[0]} version={row[1]}"
