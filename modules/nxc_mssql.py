"""NXC-backed MSSQL module."""

from modules.nxc_base import NxcModule


class NxcMSSQLModule(NxcModule):
    name = "nxc_mssql"
    nxc_protocol = "mssql"
    default_port = 1433
    alternate_ports = [1434]
