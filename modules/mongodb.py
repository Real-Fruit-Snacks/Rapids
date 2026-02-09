"""MongoDB service module using pymongo."""

from typing import Optional
from urllib.parse import quote_plus

from pymongo import MongoClient
from pymongo.errors import OperationFailure, ConnectionFailure, ServerSelectionTimeoutError

from core.models import Credential, Target
from modules.base import ServiceModule


class MongoDBModule(ServiceModule):
    name = "mongodb"
    default_port = 27017
    alternate_ports = [27018, 27019]

    def test_credential(self, target: Target, credential: Credential, timeout: int = 5, **kwargs) -> bool:
        port = target.port or self.default_port
        # URL-encode the password to handle special characters
        encoded_pass = quote_plus(credential.password)
        encoded_user = quote_plus(credential.username)
        uri = f"mongodb://{encoded_user}:{encoded_pass}@{target.host}:{port}/?authSource=admin"

        try:
            client = MongoClient(
                uri,
                serverSelectionTimeoutMS=timeout * 1000,
                connectTimeoutMS=timeout * 1000,
                socketTimeoutMS=timeout * 1000,
            )
            # Force a connection attempt
            client.admin.command("ping")
            client.close()
            return True
        except OperationFailure as e:
            if e.code == 18 or "Authentication failed" in str(e):
                return False
            raise
        except ServerSelectionTimeoutError:
            raise TimeoutError(f"MongoDB connection to {target.host}:{port} timed out")
        except ConnectionFailure as e:
            if "timed out" in str(e).lower():
                raise TimeoutError(str(e))
            raise

    def verify_access(self, target: Target, credential: Credential, timeout: int = 5, **kwargs) -> Optional[str]:
        port = target.port or self.default_port
        encoded_pass = quote_plus(credential.password)
        encoded_user = quote_plus(credential.username)
        uri = f"mongodb://{encoded_user}:{encoded_pass}@{target.host}:{port}/?authSource=admin"
        try:
            client = MongoClient(
                uri,
                serverSelectionTimeoutMS=timeout * 1000,
                connectTimeoutMS=timeout * 1000,
                socketTimeoutMS=timeout * 1000,
            )
            info = client.server_info()
            dbs = client.list_database_names()
            client.close()
            version = info.get("version", "?")
            return f"version={version} dbs={','.join(dbs)}"
        except Exception:
            return None
