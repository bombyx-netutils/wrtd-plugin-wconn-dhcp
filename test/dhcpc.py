#!/usr/bin/python3
# -*- coding: utf-8; tab-width: 4; indent-tabs-mode: t -*-

import threading


class DhcpClient(threading.Thread):

    DHCP_STATE_INIT                         = 0
    DHCP_STATE_SELECTING                    = 1
    DHCP_STATE_REQUESTING                   = 4
    DHCP_STATE_BOUND                        = 5
    DHCP_STATE_RENEWING                     = 6
    DHCP_STATE_REBINDING                    = 7

    def __init__(self, ifname, backend=None):
        super(DhcpClient, self).__init__()

        self.ifname = ifname
        self.backend = DefaultBackEnd() if backend is None else backend

        self.bReportHostname = False

        self.state = None
        self.lease = None

        self.efd_abort = None
        self.tfd_resend = None
        self.tfd_t1 = None
        self.tfd_t2 = None
        self.tfd_expire = None
        self.attempt = None

        self.sock = None

    def enableReportHostname(self):
        self.bReportHostname = True

    def run(self):
        try:
            self._client_start()
            while True:
                events = poll.poll()
                for (fd, event) in events:
                    if fd == self.efd_abort:                   # fixme: may need .fileno(), same below
                        break
                    elif fd == self.tfd_resend:
                        self._client_timeout_resend()
                    elif fd == self.tfd_t1:
                        self._client_timeout_t1()
                    elif fd == self.tfd_t2:
                        self._client_timeout_t2()
                    elif fd == self.tfd_expire:
                        self._client_timeout_expire()
                    elif fd == self.sock and event & select.POLLIN:
                        self._client_handle_message()
                    elif fd == self.sock and event & select.POLLPRI:
                        assert False
                    else:
                        assert False
        finally:
            self._client_stop()

    def stop(self):
        self.efd_abort.write(1)

    def _client_start(self):
        self.xid = random()

        self.state = DHCP_STATE_INIT
        self.attempt = 1

        self.sock = DHCP4Socket(self.ifname)

        self.efd_abort = linuxfd.eventfd()

        self.tfd_resend = linuxfd.timerfd()
        self.tfd_t1 = linuxfd.timerfd()
        self.tfd_t2 = linuxfd.timerfd()
        self.tfd_expire = linuxfd.timerfd()

        self.poll = select.poll()
        self.poll.register(self.sock, select.POLLIN | select.POLLPRI)
        self.poll.register(self.efd_abort, select.POLLIN)
        self.poll.register(self.tfd_resend, select.POLLIN)
        self.poll.register(self.tfd_t1, select.POLLIN)
        self.poll.register(self.tfd_t2, select.POLLIN)
        self.poll.register(self.tfd_expire, select.POLLIN)

        self.tfd_resend.settime(0, 0)

    def _client_stop(self):
        self.poll = None

        if self.tfd_expire is not None:
            self.tfd_expire.close()
            self.tfd_expire = None

        if self.tfd_t2 is not None:
            self.tfd_t2.close()
            self.tfd_t2 = None

        if self.tfd_t1 is not None:
            self.tfd_t1.close()
            self.tfd_t1 = None

        if self.tfd_resend is not None:
            self.tfd_resend.close()
            self.tfd_resend = None

        if self.efd_abort is not None:
            self.efd_abort.close()
            self.efd_abort = None

        if self.sock is not None:
            self.sock.close()
            self.sock = None

        self.attempt = None
        self.state = None

        self.xid = None

    def _client_timeout_resend(self):
        # calculate next timeout
        if self.state == DHCP_STATE_RENEWING:
            time_left = (client.lease__t2 - client.lease__t1) / 2
            time_left = max(time_left, 60)
            next_timeout = time_left * USEC_PER_SEC;
        elif self.state == DHCP_STATE_REBINDING:
            time_left = (client.lease__lifetime - client.lease__t2) / 2
            time_left = max(time_left, 60)
            next_timeout = time_left * USEC_PER_SEC;
        elif self.state in [DHCP_STATE_INIT, DHCP_STATE_SELECTING, DHCP_STATE_REQUESTING, DHCP_STATE_BOUND]:
            if client.attempt < 64:
                client.attempt *= 2
            next_timeout = (client.attempt - 1) * USEC_PER_SEC;
        else:
            assert False
        next_timeout += (random_u32() & 0x1fffff)

        # do work
        try:
            if self.state == DHCP_STATE_INIT:
                client_send_discover()
                self.state = DHCP_STATE_SELECTING
                self.attempt = 1
            elif self.state == DHCP_STATE_SELECTING:
                client_send_discover()
            elif self.state in [DHCP_STATE_REQUESTING, DHCP_STATE_RENEWING, DHCP_STATE_REBINDING]:
                client_send_request()
                self.request_sent = time_now
            elif self.state == DHCP_STATE_BOUND:
                pass
            else:
                assert False
        except:
            if self.attempt >= 64:
                self.efd_abort.write(1)     # stop dhcp client
                return

        # start next timeout
        self.tfd_resend.settime(next_timeout, 0)

    def _client_timeout_t1(self):
        # log_dhcp6_client(client, "Timeout T1");
        self.state = DHCP_STATE_RENEWING
        self.attempt = 1
        self.tfd_resend.settime(next_timeout, 0)

    def _client_timeout_t2(self):
        # log_dhcp6_client(client, "Timeout T2");
        client.state = DHCP_STATE_REBINDING
        client.attempt = 1
        self.tfd_resend.settime(next_timeout, 0)

    def _client_timeout_expire(self):
        self.onExpired()
        _client_start(client)

    def client_send_discover(self):
        assert self.state in [DHCP_STATE_INIT, DHCP_STATE_SELECTING]

        ipaddr = None
        macaddr = None
        if True:
            addrDict = netifaces.ifaddresses(self.ifname)
            if netifaces.AF_INET in addrDict:
                ipaddr = addrDict[netifaces.AF_INET]["addr"]
            assert netifaces.AF_PKT in addrDict
            macAddr = addrDict[netifaces.AF_INET]["addr"]

        pkt = dhcp4msg({
            'op': BOOTREQUEST,
            'chaddr': macAddr,
            'options': {
                'message_type': DHCPDISCOVER,
                'parameter_list': [
                    1,                          # DHCP_OPTION_SUBNET_MASK
                    3,                          # DHCP_OPTION_ROUTER
                    6,                          # DHCP_OPTION_DOMAIN_NAME_SERVER
                    12,                         # DHCP_OPTION_HOST_NAME
                    15,                         # DHCP_OPTION_DOMAIN_NAME
                    28,                         # DHCP_OPTION_BROADCAST
                ],
            },
        })
        # fixme: add SD_DHCP_OPTION_REQUESTED_IP_ADDRESS
        # fixme: add SD_DHCP_OPTION_HOST_NAME

        # We currently ignore:
        # The client SHOULD wait a random time between one and ten seconds to
        # desynchronize the use of DHCP at startup.
        self.sock.put(pkt)

    def client_send_request(self):
        assert self.state in [DHCP_STATE_REQUESTING, DHCP_STATE_RENEWING, DHCP_STATE_REBINDING]

        ipaddr = None
        macaddr = None
        if True:
            addrDict = netifaces.ifaddresses(self.ifname)
            if netifaces.AF_INET in addrDict:
                ipaddr = addrDict[netifaces.AF_INET]["addr"]
            assert netifaces.AF_PKT in addrDict
            macAddr = addrDict[netifaces.AF_INET]["addr"]

        optionList = [
            1,                          # DHCP_OPTION_SUBNET_MASK
            3,                          # DHCP_OPTION_ROUTER
            6,                          # DHCP_OPTION_DOMAIN_NAME_SERVER
            12,                         # DHCP_OPTION_HOST_NAME
            15,                         # DHCP_OPTION_DOMAIN_NAME
            28,                         # DHCP_OPTION_BROADCAST
        ]

        if self.state == DHCP_STATE_REQUESTING:
            pkt = dhcp4msg({
                'op': BOOTREQUEST,
                'chaddr': macaddr,
                'options': {
                    'message_type': DHCPREQUEST,
                    'requested_ip': reply['yiaddr'],
                    'server_id': reply['options']['server_id'],
                    'parameter_list': optionList,
                },
            })
            # log_dhcp_client(client, "REQUEST (requesting)");
        elif self.state == DHCP_STATE_RENEWING:
            pkt = dhcp4msg({
                'op': BOOTREQUEST,
                'chaddr': macaddr,
                'options': {
                    'message_type': DHCPREQUEST,
                    'ciaddr': ipaddr,
                    'parameter_list': optionList,
                },
            })
            # log_dhcp_client(client, "REQUEST (renewing)");
        elif self.state == DHCP_STATE_REBINDING:
            pkt = dhcp4msg({
                'op': BOOTREQUEST,
                'chaddr': macaddr,
                'options': {
                    'message_type': DHCPREQUEST,
                    'ciaddr': ipaddr,
                    'parameter_list': optionList,
                },
            })
            # log_dhcp_client(client, "REQUEST (rebinding)");
        else:
            assert False

        # fixme: add SD_DHCP_OPTION_HOST_NAME

        self.sock.put(pkt)


    def _client_handle_message(self, message):
        if self.state == DHCP_STATE_SELECTING:
            try:
                self.__client_handle_offer(message)
                self.state = DHCP_STATE_REQUESTING
                self.attempt = 1
                self.tfd_resend.settime(0, 0)
            except InvalidPacket:
                pass        # invalid message, let's ignore it
        elif self.state in [DHCP_STATE_REQUESTING, DHCP_STATE_RENEWING, DHCP_STATE_REBINDING]:
            try:
                self.__client_handle_ack(message)

                self.state = DHCP_STATE_BOUND
                self.attempt = 1

                if self.lease.lifetime != 0xffffffff:
                    # convert the various timeouts from relative (secs) to absolute (usecs)
                    lifetime_timeout = client_compute_timeout(client, self.lease.lifetime, 1)
                    t1_timeout = None
                    t2_timeout = None
                    if self.lease.t1 > 0 and self.lease.t2 > 0:
                        # both T1 and T2 are given
                        if self.lease.t1 < self.lease.t2 and self.lease.t2 < self.lease.lifetime:
                            # they are both valid
                            t2_timeout = client_compute_timeout(client, self.lease.t2, 1);
                            t1_timeout = client_compute_timeout(client, self.lease.t1, 1);
                        else:
                            # discard both
                            t2_timeout = client_compute_timeout(client, self.lease.lifetime, 7.0 / 8.0);
                            self.lease.t2 = (self.lease.lifetime * 7) / 8;
                            t1_timeout = client_compute_timeout(client, self.lease.lifetime, 0.5);
                            self.lease.t1 = self.lease.lifetime / 2;
                    elif self.lease.t2 > 0 and self.lease.t2 < self.lease.lifetime:
                        # only T2 is given, and it is valid
                        t2_timeout = client_compute_timeout(client, self.lease.t2, 1);
                        t1_timeout = client_compute_timeout(client, self.lease.lifetime, 0.5);
                        self.lease.t1 = self.lease.lifetime / 2;
                        if t2_timeout <= t1_timeout:
                            # the computed T1 would be invalid, so discard T2
                            t2_timeout = client_compute_timeout(client, self.lease.lifetime, 7.0 / 8.0);
                            self.lease.t2 = (self.lease.lifetime * 7) / 8;
                    elif self.lease.t1 > 0 and self.lease.t1 < self.lease.lifetime:
                        # only T1 is given, and it is valid
                        t1_timeout = client_compute_timeout(client, self.lease.t1, 1);
                        t2_timeout = client_compute_timeout(client, self.lease.lifetime, 7.0 / 8.0);
                        self.lease.t2 = (self.lease.lifetime * 7) / 8;
                        if t2_timeout <= t1_timeout:
                            # the computed T2 would be invalid, so discard T1
                            t2_timeout = client_compute_timeout(client, self.lease.lifetime, 0.5);
                            self.lease.t2 = self.lease.lifetime / 2;
                    else:
                        # fall back to the default timeouts
                        t1_timeout = client_compute_timeout(client, self.lease.lifetime, 0.5);
                        self.lease.t1 = self.lease.lifetime / 2;
                        t2_timeout = client_compute_timeout(client, self.lease.lifetime, 7.0 / 8.0);
                        self.lease.t2 = (self.client_compute_timeoutlease.lifetime * 7) / 8;

                    self.tfd_expire.settime(lifetime_timeout)     # fixme unit?
                    
                    if lifetime_timeout <= time_now:
                        return
                    self.tfd_t2.settime(t2_timeout)

                    if t2_timeout <= time_now:
                        return
                    self.tfd_t1.settime(t1_timeout)
            except NakPacket:
                self._client_stop()
                self._client_start()
            except InvalidPacket:
                pass        # invalid message, let's ignore it

        elif self.state == DHCP_STATE_BOUND:
            try:
                self.__client_handle_forcerenew(message)
                self._client_timeout_t1()
            except InvalidPacket:
                pass        # invalid message, let's ignore it
        elif self.state == DHCP_STATE_INIT:
            pass            # invalid message, let's ignore it
        else:
            assert False

    def __client_handle_offer(self):
        pass

        # if (client->client_id_len) {
        #         r = dhcp_lease_set_client_id(lease,
        #                                      (uint8_t *) &client->client_id,
        #                                      client->client_id_len);
        #         if (r < 0)
        #                 return r;
        # }

        # r = dhcp_option_parse(offer, len, dhcp_lease_parse_options, lease, NULL);
        # if (r != DHCP_OFFER) {
        #         log_dhcp_client(client, "received message was not an OFFER, ignoring");
        #         return -ENOMSG;
        # }

        # lease->next_server = offer->siaddr;
        # lease->address = offer->yiaddr;

        # if (lease->address == 0 ||
        #     lease->server_address == 0 ||
        #     lease->lifetime == 0) {
        #         log_dhcp_client(client, "received lease lacks address, server address or lease lifetime, ignoring");
        #         return -ENOMSG;
        # }

        # if (!lease->have_subnet_mask) {
        #         r = dhcp_lease_set_default_subnet_mask(lease);
        #         if (r < 0) {
        #                 log_dhcp_client(client, "received lease lacks subnet "
        #                                 "mask, and a fallback one can not be "
        #                                 "generated, ignoring");
        #                 return -ENOMSG;
        #         }
        # }

        # log_dhcp_client(client, "OFFER");


    def __client_handle_ack(self):
        pass


#         r = dhcp_lease_new(&lease);
#         if (r < 0)
#                 return r;

#         if (client->client_id_len) {
#                 r = dhcp_lease_set_client_id(lease,
#                                              (uint8_t *) &client->client_id,
#                                              client->client_id_len);
#                 if (r < 0)
#                         return r;
#         }

#         r = dhcp_option_parse(ack, len, dhcp_lease_parse_options, lease, &error_message);
#         if (r == DHCP_NAK) {
#                 log_dhcp_client(client, "NAK: %s", strna(error_message));
#                 return -EADDRNOTAVAIL;
#         }

#         if (r != DHCP_ACK) {
#                 log_dhcp_client(client, "received message was not an ACK, ignoring");
#                 return -ENOMSG;
#         }

#         lease->next_server = ack->siaddr;

#         lease->address = ack->yiaddr;

#         if (lease->address == INADDR_ANY ||
#             lease->server_address == INADDR_ANY ||
#             lease->lifetime == 0) {
#                 log_dhcp_client(client, "received lease lacks address, server "
#                                 "address or lease lifetime, ignoring");
#                 return -ENOMSG;
#         }

#         if (lease->subnet_mask == INADDR_ANY) {
#                 r = dhcp_lease_set_declient_compute_timeoutfault_subnet_mask(lease);
#                 if (r < 0) {
#                         log_dhcp_client(client, "received lease lacks subnet "
#                                         "mask, and a fallback one can not be "
#                                         "generated, ignoring");
#                         return -ENOMSG;
#                 }
#         }

#         r = SD_DHCP_CLIENT_EVENT_IP_ACQUIRE;
#         if (client->lease) {
#                 if (client->lease->address != lease->address ||
#                     client->lease->subnet_mask != lease->subnet_mask ||
#                     client->lease->router != lease->router) {
#                         r = SD_DHCP_CLIENT_EVENT_IP_CHANGE;
#                 } else
#                         r = SD_DHCP_CLIENT_EVENT_RENEW;

#                 client->lease = sd_dhcp_lease_unref(client->lease);
#         }

#         client->lease = lease;
#         lease = NULL;


#         return r;


    def __client_handle_forcerenew(self):
        pass


class Lease:

    def __init__(self):
        self.t1 = None
        self.t2 = None
        self.lifetime = None

        self.address = None
        self.server_address = None
        self.router = None
        self.next_server = None

        self.subnet_mask = None
        self.broadcast = None

        self.dns = None

        self.ntp = None

        self.static_routes = None

        self.mtu = None

        self.domainname = None
        self.search_domains = None
        self.hostname = None
        self.root_path = None

        self.client_id = None

        self.vendor_specific = None

        self.timezone = None


class DefaultBackEnd:

    def get_saved_lease(self):
        return None

    def lease_acquired(self, ifname, lease):
        pass

    def lease_updated(self, ifname, lease):
        pass

    def lease_expired(self, ifname):
        pass
