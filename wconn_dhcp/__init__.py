#!/usr/bin/python3
# -*- coding: utf-8; tab-width: 4; indent-tabs-mode: t -*-

import os
import time
import fcntl
import socket
import struct
import logging
import netifaces
import subprocess
from pyroute2.dhcp.dhcp4socket import DHCP4Socket



def get_plugin_list():
    return [
        "generic-dhcp",
    ]


def get_plugin(name):
    if name == "generic-dhcp":
        return _PluginObject(None)
    else:
        assert False


class _PluginObject:

    def __init__(self):
        pass

    def init2(self, cfg, tmpDir, ownResolvConf, prefixCheckFunc):
        self.cfg = cfg
        self.tmpDir = tmpDir
        self.ownResolvConf = ownResolvConf
        self.prefixCheckFunc = prefixCheckFunc
        self.dhClient = None

    def start(self):
        pass

    def stop(self):
        if self.dhClient is not None:
            self.dhClient.stop()
            self.dhClient = None
        _Util.setInterfaceUpDown(self.cfg["interface"], False)

    def get_out_interface(self):
        return None

    def interface_appear(self, ifname):
        if ifname != self.cfg["interface"]:
            return False

        _Util.setInterfaceUpDown(self.cfg["interface"], True)

        assert self.dhClient is None
        self.dhClient = _DhcpClient(self.cfg["interface"])
        self.dhClient.start()

        logging.info("WAN: Internet interface \"%s\" is managed." % (self.cfg["interface"]))
        return True

    def interface_disappear(self, ifname):
        assert ifname == self.cfg["interface"]
        if self.dhClient is not None:
            self.dhClient.stop()
            self.dhClient = None


class _Util:

    @staticmethod
    def setInterfaceUpDown(ifname, upOrDown):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            ifreq = struct.pack("16sh", ifname.encode("ascii"), 0)
            ret = fcntl.ioctl(s.fileno(), 0x8913, ifreq)
            flags = struct.unpack("16sh", ret)[1]                   # SIOCGIFFLAGS

            if upOrDown:
                flags |= 0x1
            else:
                flags &= ~0x1

            ifreq = struct.pack("16sh", ifname.encode("ascii"), flags)
            fcntl.ioctl(s.fileno(), 0x8914, ifreq)                  # SIOCSIFFLAGS
        finally:
            s.close()





