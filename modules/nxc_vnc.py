"""NXC-backed VNC module (new — no library equivalent)."""

from modules.nxc_base import NxcModule


class NxcVNCModule(NxcModule):
    name = "nxc_vnc"
    nxc_protocol = "vnc"
    default_port = 5900
    alternate_ports = [5901, 5902]
