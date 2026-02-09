"""NXC-backed SSH module."""

from modules.nxc_base import NxcModule


class NxcSSHModule(NxcModule):
    name = "nxc_ssh"
    nxc_protocol = "ssh"
    default_port = 22
    alternate_ports = [2222]
