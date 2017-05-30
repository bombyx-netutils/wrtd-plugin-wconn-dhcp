#!/usr/bin/python3
# -*- coding: utf-8; tab-width: 4; indent-tabs-mode: t -*-

import os
import time
import fcntl
import socket
import struct
import logging
import netifaces
import ipaddress
import subprocess


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

    def init2(self, cfg, tmpDir, ownResolvConf, upCallback, downCallback):
        self.cfg = cfg
        self.tmpDir = tmpDir
        self.ownResolvConf = ownResolvConf
        self.upCallback = upCallback
        self.downCallback = downCallback
        self.logger = logging.getLogger(self.__module__ + "." + self.__class__.__name__)
        self.proc = None

    def start(self):
        self.logger.info("Started.")

    def stop(self):
        if self.proc is not None:
            self.proc.terminate()
            self.proc.join()
            self.proc = None
            _Util.setInterfaceUpDown(self.cfg["interface"], False)
            self.downCallback()
            self.logger.info("Interface \"%s\" unmanaged." % (self.cfg["interface"]))
        self.logger.info("Stopped.")

    def is_alive(self):
        return self.proc is not None and netifaces.AF_INET in netifaces.ifaddresses(self.cfg["interface"])

    def get_interface(self):
        if self.is_alive():
            return self.cfg["interface"]
        else:
            return None

    def get_prefix_list(self):
        if self.is_alive():
            t = netifaces.ifaddresses(self.cfg["interface"])
            netobj = ipaddress.IPv4Network(t[netifaces.AF_INET]["addr"], t[netifaces.AF_INET]["netmask"], False)
            return [(str(netobj.address), str(netobj.netmask))]
        else:
            return None

    def interface_appear(self, ifname):
        if ifname != self.cfg["interface"]:
            return False

        assert self.proc is None
        _Util.setInterfaceUpDown(self.cfg["interface"], True)

        # create dhclient.conf, copied from nm-dhcp-dhclient-utils.c in networkmanager-1.4.4
        cfgf = os.path.join(self.tmpDir, "dhclient.conf")
        with open(cfgf, "w") as f:
            buf = ""
            buf += "send host-name \"%s\";\n" % (socket.gethostname())
            buf += "\n"
            buf += "option rfc3442-classless-static-routes code 121 = array of unsigned integer 8;\n"
            buf += "option wpad code 252 = string;\n"
            buf += "\n"
            buf += "also request rfc3442-classless-static-routes;\n"
            buf += "also request static-routes;\n"
            buf += "also request wpad;\n"
            buf += "also request ntp-servers;\n"
            f.write(buf)

        self.proc = subprocess.Popen([
            "/usr/bin/python3",
            os.path.join(os.path.dirname(os.path.realpath(__file__)), "subproc_dhclient.py"),
            self.tmpDir,
            cfgf,
            self.cfg["interface"],
            self.ownResolvConf,
        ])

        # wait for ip address
        i = 0
        while True:
            if netifaces.AF_INET not in netifaces.ifaddresses(self.cfg["interface"]):
                if i >= 10:
                    raise Exception("IP address allocation time out.")
                time.sleep(1.0)
                i += 1
                continue
            break

        self.logger.info("Interface \"%s\" managed." % (self.cfg["interface"]))
        self.upCallback()
        return True

    def interface_disappear(self, ifname):
        assert ifname == self.cfg["interface"]
        if self.proc is not None:
            self.proc.terminate()
            self.proc.wait()
            self.proc = None
        self.downCallback()
        self.logger.info("Interface \"%s\" unmanaged." % (self.cfg["interface"]))


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
