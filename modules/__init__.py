"""Module registry with auto-discovery."""

import importlib
import pkgutil
from pathlib import Path
from typing import Dict, List, Optional, Type

from .base import ServiceModule


class ModuleRegistry:
    """Auto-discovers and manages service modules."""

    _modules: Dict[str, Type[ServiceModule]] = {}
    _discovered: bool = False

    _skipped: List[str] = []
    _skipped_packages: List[str] = []

    # Map module file names to the pip package needed
    _PIP_MAP: Dict[str, str] = {
        "cassandra_mod": "cassandra-driver",
        "memcached": "pymemcache",
        "mongodb": "pymongo",
        "oracle": "oracledb",
        "snmp": "pysnmp",
        "winrm_mod": "pywinrm",
        "kerberos_mod": "impacket",
        "ldap_mod": "ldap3",
        "redis_mod": "redis",
        "mqtt": "paho-mqtt",
        "mysql": "pymysql",
        "postgres": "psycopg2-binary",
        "mssql": "impacket",
        "smb": "impacket",
        "rdp": "impacket",
        "elasticsearch": "requests",
        "couchdb": "requests",
        "http_basic": "requests",
        "ssh": "paramiko",
        "vnc": "pycryptodome",
        "ipmi": None,  # uses ipmitool CLI, no pip package
        "wmi": None,  # uses nxc CLI, no pip package
    }

    @classmethod
    def discover(cls) -> None:
        """Auto-discover all ServiceModule subclasses in this package."""
        if cls._discovered:
            return

        cls._skipped = []
        cls._skipped_packages = []
        package_path = str(Path(__file__).parent)
        for importer, modname, ispkg in pkgutil.iter_modules([package_path]):
            if modname in ("__init__", "base"):
                continue
            try:
                importlib.import_module(f".{modname}", package=__name__)
            except ImportError as e:
                cls._skipped.append(modname)
                pkg = cls._PIP_MAP.get(modname)
                if pkg and pkg not in cls._skipped_packages:
                    cls._skipped_packages.append(pkg)

        for subclass in cls._all_subclasses(ServiceModule):
            if subclass.name:  # skip abstract bases like NxcModule
                cls._modules[subclass.name] = subclass

        cls._discovered = True

    @classmethod
    def print_skipped(cls, console) -> None:
        """Print a summary of skipped modules with install hint."""
        if cls._skipped:
            console.print(f"  [dim]Skipped modules (missing deps): {', '.join(cls._skipped)}[/dim]")
            if cls._skipped_packages:
                console.print(f"  [dim]Install with: pip install {' '.join(cls._skipped_packages)}[/dim]")

    @staticmethod
    def _all_subclasses(base: Type[ServiceModule]) -> List[Type[ServiceModule]]:
        """Recursively collect all subclasses of base."""
        result = []
        for sub in base.__subclasses__():
            result.append(sub)
            result.extend(ModuleRegistry._all_subclasses(sub))
        return result

    @classmethod
    def get_module(cls, name: str) -> Optional[Type[ServiceModule]]:
        cls.discover()
        return cls._modules.get(name)

    @classmethod
    def get_all(cls) -> Dict[str, Type[ServiceModule]]:
        cls.discover()
        return dict(cls._modules)

    @classmethod
    def get_for_port(cls, port: int) -> List[Type[ServiceModule]]:
        """Return modules whose default or alternate ports match."""
        cls.discover()
        matches = []
        for mod_cls in cls._modules.values():
            if mod_cls.default_port == port or port in mod_cls.alternate_ports:
                matches.append(mod_cls)
        return matches
