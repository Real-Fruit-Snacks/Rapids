"""Cassandra service module using cassandra-driver."""

from typing import Optional

from cassandra.cluster import Cluster, NoHostAvailable
from cassandra.auth import PlainTextAuthProvider

from core.models import Credential, Target
from modules.base import ServiceModule


class CassandraModule(ServiceModule):
    name = "cassandra"
    default_port = 9042
    alternate_ports = [9142]

    def test_credential(self, target: Target, credential: Credential, timeout: int = 5, **kwargs) -> bool:
        port = target.port or self.default_port
        auth = PlainTextAuthProvider(
            username=credential.username,
            password=credential.password,
        )
        cluster = Cluster(
            contact_points=[target.host],
            port=port,
            auth_provider=auth,
            connect_timeout=timeout,
        )
        try:
            session = cluster.connect()
            session.shutdown()
            cluster.shutdown()
            return True
        except NoHostAvailable as e:
            err = str(e).lower()
            if "authentication" in err or "credentials" in err:
                return False
            if "connection refused" in err or "refused" in err:
                raise ConnectionRefusedError(f"Cassandra connection to {target.host}:{port} refused")
            if "timed out" in err or "timeout" in err:
                raise TimeoutError(str(e))
            raise
        except Exception as e:
            err = str(e).lower()
            if "connection refused" in err or "refused" in err:
                raise ConnectionRefusedError(f"Cassandra connection to {target.host}:{port} refused")
            if "timed out" in err or "timeout" in err:
                raise TimeoutError(str(e))
            raise
        finally:
            cluster.shutdown()

    def verify_access(self, target: Target, credential: Credential, timeout: int = 5, **kwargs) -> Optional[str]:
        port = target.port or self.default_port
        auth = PlainTextAuthProvider(username=credential.username, password=credential.password)
        cluster = Cluster(contact_points=[target.host], port=port, auth_provider=auth, connect_timeout=timeout)
        try:
            session = cluster.connect()
            row = session.execute("SELECT cluster_name, release_version FROM system.local").one()
            session.shutdown()
            cluster.shutdown()
            if row:
                return f"cluster={row.cluster_name} version={row.release_version}"
            return "Authenticated"
        except Exception:
            cluster.shutdown()
            return None
