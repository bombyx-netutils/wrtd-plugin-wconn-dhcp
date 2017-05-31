#!/usr/bin/python3
# -*- coding: utf-8; tab-width: 4; indent-tabs-mode: t -*-

import os
import fcntl
import socket
import struct
import logging
import pyroute2
import netifaces
from dhcpc import DhcpClient


def get_plugin_list():
    return [
        "generic-dhcp",
    ]


def get_plugin(name):
    if name == "generic-dhcp":
        return _PluginObject()
    else:
        assert False


class _PluginObject:

    def init2(self, cfg, tmpDir, ownResolvConf, prefixCheckFunc):
        self.cfg = cfg
        self.tmpDir = tmpDir
        self.ownResolvConf = ownResolvConf
        self.prefixCheckFunc = prefixCheckFunc

        self.logger = logging.getLogger(__name__ + ".generic-dhcp")
        self.dhClient = None

    def start(self):
        self.logger.info("Started.")

    def stop(self):
        if self.dhClient is not None:
            self.dhClient.stop()
            self.dhClient = None
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

        with pyroute2.IPRoute() as ip:
            idx = ip.link_lookup(ifname=self.cfg["interface"])[0]
            ip.link("set", index=idx, state="up")

        assert self.dhClient is None
        self.dhClient = DhcpClient(self.cfg["interface"], _BackEnd(self))
        self.dhClient.start()

        self.logger.info("Interface \"%s\" managed." % (self.cfg["interface"]))
        return True

    def interface_disappear(self, ifname):
        assert ifname == self.cfg["interface"]
        if self.dhClient is not None:
            self.dhClient.stop()
            self.dhClient = None
        self.logger.info("Interface \"%s\" unmanaged." % (self.cfg["interface"]))


class _BackEnd:

    def __init__(self, pObj):
        self.pObj = pObj
        self.addr = None

    def get_saved_lease(self):
        return None

    def lease_acquired(self, ifname, lease):
        # delete old address
        if self.addr is not None:
            with pyroute2.IPRoute() as ip:
                idx = ip.link_lookup(ifname=ifname)[0]
                ip.addr("delete", index=idx, address=self.addr)
            self.addr = None

        # set new address, default route and dns information
        with pyroute2.IPRoute() as ipp:
            idx = ipp.link_lookup(ifname=ifname)[0]
            ipp.addr("add", index=idx, address=lease.address, mask=lease.subnet_mask, broadcast=lease.broadcast)
            ipp.route("add", dst="0.0.0.0/0", gateway=lease.router[0], oif=idx)
        self.addr = lease.address

    def lease_updated(self, ifname, lease):
        self.lease_acquired(ifname, lease)

    def lease_destroyed(self, ifname):
        if self.addr is not None:
            with pyroute2.IPRoute() as ip:
                idx = ip.link_lookup(ifname=ifname)[0]
                ip.addr("delete", index=idx, address=self.addr)
            self.addr = None
