"""NXC-backed WinRM module."""

from modules.nxc_base import NxcModule


class NxcWinRMModule(NxcModule):
    name = "nxc_winrm"
    nxc_protocol = "winrm"
    default_port = 5985
    alternate_ports = [5986]
