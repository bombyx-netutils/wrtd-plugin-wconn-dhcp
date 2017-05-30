#!/usr/bin/python3
# -*- coding: utf-8; tab-width: 4; indent-tabs-mode: t -*-

import os
import time
import socket
import logging
import pyroute2
import netifaces
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

    def init2(self, cfg, tmpDir, ownResolvConf):
        self.cfg = cfg
        self.tmpDir = tmpDir
        self.ownResolvConf = ownResolvConf
        self.logger = logging.getLogger(self.__module__ + "." + self.__class__.__name__ + ".generic-dhcp")
        self.proc = None

    def start(self):
        self.logger.info("Started.")

    def stop(self):
        if self.proc is not None:
            self.proc.terminate()
            self.proc.join()
            self.proc = None
            with pyroute2.IPRoute() as ip:
                idx = ip.link_lookup(ifname=self.cfg["interface"])[0]
                ip.link("set", index=idx, state="down")
            self.logger.info("Interface \"%s\" unmanaged." % (self.cfg["interface"]))
        self.logger.info("Stopped.")

    def get_out_interface(self):
        return None

    def interface_appear(self, ifname):
        if ifname != self.cfg["interface"]:
            return False

        assert self.proc is None

        with pyroute2.IPRoute() as ip:
            idx = ip.link_lookup(ifname=self.cfg["interface"])[0]
            ip.link("set", index=idx, state="up")

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
            t = netifaces.ifaddresses(self.cfg["interface"])
            if 2 not in t:
                if i >= 10:
                    raise Exception("IP address allocation time out.")
                time.sleep(1.0)
                i += 1
                continue
            break

        self.logger.info("Interface \"%s\" managed." % (self.cfg["interface"]))
        return True

    def interface_disappear(self, ifname):
        assert ifname == self.cfg["interface"]
        if self.proc is not None:
            self.proc.terminate()
            self.proc.wait()
            self.proc = None
        self.logger.info("Interface \"%s\" unmanaged." % (self.cfg["interface"]))
