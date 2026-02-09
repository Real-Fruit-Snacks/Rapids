"""NXC-backed RDP module."""

from modules.nxc_base import NxcModule


class NxcRDPModule(NxcModule):
    name = "nxc_rdp"
    nxc_protocol = "rdp"
    default_port = 3389
    alternate_ports = []
