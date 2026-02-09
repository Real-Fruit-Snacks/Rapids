"""NXC-backed FTP module."""

from modules.nxc_base import NxcModule


class NxcFTPModule(NxcModule):
    name = "nxc_ftp"
    nxc_protocol = "ftp"
    default_port = 21
    alternate_ports = [2121]
