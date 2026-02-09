"""NXC-backed WMI module (new — no library equivalent)."""

from modules.nxc_base import NxcModule


class NxcWMIModule(NxcModule):
    name = "nxc_wmi"
    nxc_protocol = "wmi"
    default_port = 135
    alternate_ports = []
