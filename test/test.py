import threading


class _DhcpClient(threading.Thread):

    DHCP_STATE_INIT                         = 0
    DHCP_STATE_SELECTING                    = 1
    DHCP_STATE_REQUESTING                   = 4
    DHCP_STATE_BOUND                        = 5
    DHCP_STATE_RENEWING                     = 6
    DHCP_STATE_REBINDING                    = 7

    def __init__(self, ifname):
        self.ifname = ifname
        self.bReportHostname = False

        self.state = None
        self.lease_t1 = None
        self.lease_t2 = None
        self.lease_lifetime = None


        # bad
        self.timeout_resend = None
        self.timeout_t1 = None
        self.timeout_t2 = None
        self.timeout_expire = None
        # end bad

        self.tfd_resend = None
        self.tfd_t1 = None
        self.tfd_t2 = None
        self.tfd_expire = None
        self.attempt = None

        self.sock = None




        self.onStop = None
        self.onIpAcquire = None
        self.onIpChange = None
        self.onExpired = None
        self.onRenew = None

    def enableReportHostname(self):
        self.bReportHostname = True

    def run(self):
        self._client_start()

        # fixme
        # if (client->state == DHCP_STATE_INIT)
        #         client->start_time = now(clock_boottime_or_monotonic());

        self._sendDiscover()
        while True:
            events = poll.poll(2)
            for (fd, event) in events:
                if fd == self.efd_abort:                   # fixme: need .fileno(), same below
                    self._client_stop()
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
                    assert False
                elif fd == self.sock and event & select.POLLPRI:
                    assert False
                else:
                    assert False

    def stop(self):
        self.efd_abort.write(1)

    def _client_start(self):
        self.state = DHCP_STATE_INIT
        self.attempt = 1
        self.xid = random()

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

    def _client_stop(self):
        self.onStop()

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

        self.xid = None
        self.attempt = None
        self.state = None

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
            if self.attempt >= 64
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
            assert netifaces.AF_PKT in addrDict:
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
            assert netifaces.AF_PKT in addrDict:
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
}


















    def _clientHandleMessage(self):
        if self.state == DHCP_STATE_SELECTING:
            r = client_handle_offer(client, message, len);
            if r < 0:
                return 0    # invalid message, let's ignore it

                GLib.source_remove(self.timeout_resend)
                self.state = DHCP_STATE_REQUESTING
                self.attempt = 1
                self.timeout_resend = GLib.timeout_add(0, self._client_timeout_resend)

        elif self.state in [DHCP_STATE_REQUESTING, DHCP_STATE_RENEWING, DHCP_STATE_REBINDING]:

                r = client_handle_ack(client, message, len);
                if (r >= 0) {
                        client->start_delay = 0;
                        GLib.source_remove(self.timeout_resend)
                        client->receive_message =
                                sd_event_source_unref(client->receive_message);
                        client->fd = asynchronous_close(client->fd);

                        if (IN_SET(client->state, DHCP_STATE_REQUESTING))
                                notify_event = SD_DHCP_CLIENT_EVENT_IP_ACQUIRE;
                        else if (r != SD_DHCP_CLIENT_EVENT_IP_ACQUIRE)
                                notify_event = r;

                        self.state = DHCP_STATE_BOUND
                        self.attempt = 1

                        client->last_addr = client->lease->address;

                        r = client_set_lease_timeouts(client);
                        if (r < 0) {
                                log_dhcp_client(client, "could not set lease timeouts");
                                goto error;
                        }

                        r = dhcp_network_bind_udp_socket(client->ifindex, client->lease->address, client->port);
                        if (r < 0) {
                                log_dhcp_client(client, "could not bind UDP socket");
                                goto error;
                        }

                        client->fd = r;

                        client_initialize_io_events(client, client_receive_message_udp);

                        if (notify_event) {
                                client_notify(client, notify_event);
                                if (client->state == DHCP_STATE_STOPPED)
                                        return 0;
                        }

                } else if (r == -EADDRNOTAVAIL) {
                        /* got a NAK, let's restart the client */
                        client->timeout_resend =
                                sd_event_source_unref(client->timeout_resend);

                        r = client_initialize(client);
                        if (r < 0)
                                goto error;

                        r = _client_start_delayed(client);
                        if (r < 0)
                                goto error;

                        log_dhcp_client(client, "REBOOT in %s", format_timespan(time_string, FORMAT_TIMESPAN_MAX,
                                                                                client->start_delay, USEC_PER_SEC));

                        client->start_delay = CLAMP(client->start_delay * 2,
                                                    RESTART_AFTER_NAK_MIN_USEC, RESTART_AFTER_NAK_MAX_USEC);

                        return 0;
                } else if (r == -ENOMSG)
                        /* invalid message, let's ignore it */
                        return 0;

                break;

        elif self.state == DHCP_STATE_BOUND:

                r = client_handle_forcerenew(client, message, len);
                if (r >= 0) {
                        r = client_timeout_t1(NULL, 0, client);
                        if (r < 0)
                                goto error;
                } else if (r == -ENOMSG)
                        /* invalid message, let's ignore it */
                        return 0;

                break;

        elif self.state in [DHCP_STATE_INIT, DHCP_STATE_INIT_REBOOT]:

                break;

        elif self.state ==  DHCP_STATE_STOPPED:
                r = -EINVAL;
                goto error;

    def _clientHandleOffer(self):

        r = dhcp_lease_new(&lease);
        if (r < 0)
                return r;

        if (client->client_id_len) {
                r = dhcp_lease_set_client_id(lease,
                                             (uint8_t *) &client->client_id,
                                             client->client_id_len);
                if (r < 0)
                        return r;
        }

        r = dhcp_option_parse(offer, len, dhcp_lease_parse_options, lease, NULL);
        if (r != DHCP_OFFER) {
                log_dhcp_client(client, "received message was not an OFFER, ignoring");
                return -ENOMSG;
        }

        lease->next_server = offer->siaddr;
        lease->address = offer->yiaddr;

        if (lease->address == 0 ||
            lease->server_address == 0 ||
            lease->lifetime == 0) {
                log_dhcp_client(client, "received lease lacks address, server address or lease lifetime, ignoring");
                return -ENOMSG;
        }

        if (!lease->have_subnet_mask) {
                r = dhcp_lease_set_default_subnet_mask(lease);
                if (r < 0) {
                        log_dhcp_client(client, "received lease lacks subnet "
                                        "mask, and a fallback one can not be "
                                        "generated, ignoring");
                        return -ENOMSG;
                }
        }

        sd_dhcp_lease_unref(client->lease);
        client->lease = lease;
        lease = NULL;

        log_dhcp_client(client, "OFFER");

        return 0;
}


    def _clientHandleAck(self):



        r = dhcp_lease_new(&lease);
        if (r < 0)
                return r;

        if (client->client_id_len) {
                r = dhcp_lease_set_client_id(lease,
                                             (uint8_t *) &client->client_id,
                                             client->client_id_len);
                if (r < 0)
                        return r;
        }

        r = dhcp_option_parse(ack, len, dhcp_lease_parse_options, lease, &error_message);
        if (r == DHCP_NAK) {
                log_dhcp_client(client, "NAK: %s", strna(error_message));
                return -EADDRNOTAVAIL;
        }

        if (r != DHCP_ACK) {
                log_dhcp_client(client, "received message was not an ACK, ignoring");
                return -ENOMSG;
        }

        lease->next_server = ack->siaddr;

        lease->address = ack->yiaddr;

        if (lease->address == INADDR_ANY ||
            lease->server_address == INADDR_ANY ||
            lease->lifetime == 0) {
                log_dhcp_client(client, "received lease lacks address, server "
                                "address or lease lifetime, ignoring");
                return -ENOMSG;
        }

        if (lease->subnet_mask == INADDR_ANY) {
                r = dhcp_lease_set_default_subnet_mask(lease);
                if (r < 0) {
                        log_dhcp_client(client, "received lease lacks subnet "
                                        "mask, and a fallback one can not be "
                                        "generated, ignoring");
                        return -ENOMSG;
                }
        }

        r = SD_DHCP_CLIENT_EVENT_IP_ACQUIRE;
        if (client->lease) {
                if (client->lease->address != lease->address ||
                    client->lease->subnet_mask != lease->subnet_mask ||
                    client->lease->router != lease->router) {
                        r = SD_DHCP_CLIENT_EVENT_IP_CHANGE;
                } else
                        r = SD_DHCP_CLIENT_EVENT_RENEW;

                client->lease = sd_dhcp_lease_unref(client->lease);
        }

        client->lease = lease;
        lease = NULL;


        return r;
}




static int client_set_lease_timeouts(sd_dhcp_client *client) {

    GLib.source_remove(self.timeout_t1)
    self.timeout_t1 = None
    GLib.source_remove(self.timeout_t2)
    self.timeout_t2 = None
    GLib.source_remove(self.timeout_expire)
    self.timeout_expire = None

    /* don't set timers for infinite leases */
    if (self.lease_lifetime == 0xffffffff)
            return 0;

    r = sd_event_now(client->event, clock_boottime_or_monotonic(), &time_now);
    if (r < 0)
            return r;
    assert(client->request_sent <= time_now);

    # convert the various timeouts from relative (secs) to absolute (usecs)
    lifetime_timeout = client_compute_timeout(client, self.lease_lifetime, 1)
    t1_timeout = None
    t2_timeout = None
    if self.lease_t1 > 0 and self.lease_t2 > 0:
        # both T1 and T2 are given
        if self.lease_t1 < self.lease_t2 and self.lease_t2 < self.lease_lifetime:
            # they are both valid
            t2_timeout = client_compute_timeout(client, self.lease_t2, 1);
            t1_timeout = client_compute_timeout(client, self.lease_t1, 1);
        else:
            # discard both
            t2_timeout = client_compute_timeout(client, self.lease_lifetime, 7.0 / 8.0);
            self.lease_t2 = (self.lease_lifetime * 7) / 8;
            t1_timeout = client_compute_timeout(client, self.lease_lifetime, 0.5);
            self.lease_t1 = self.lease_lifetime / 2;
    elif self.lease_t2 > 0 and self.lease_t2 < self.lease_lifetime:
        # only T2 is given, and it is valid
        t2_timeout = client_compute_timeout(client, self.lease_t2, 1);
        t1_timeout = client_compute_timeout(client, self.lease_lifetime, 0.5);
        self.lease_t1 = self.lease_lifetime / 2;
        if t2_timeout <= t1_timeout:
            # the computed T1 would be invalid, so discard T2
            t2_timeout = client_compute_timeout(client, self.lease_lifetime, 7.0 / 8.0);
            self.lease_t2 = (self.lease_lifetime * 7) / 8;
    elif self.lease_t1 > 0 and self.lease_t1 < self.lease_lifetime:
        # only T1 is given, and it is valid
        t1_timeout = client_compute_timeout(client, self.lease_t1, 1);
        t2_timeout = client_compute_timeout(client, self.lease_lifetime, 7.0 / 8.0);
        self.lease_t2 = (self.lease_lifetime * 7) / 8;
        if t2_timeout <= t1_timeout:
            # the computed T2 would be invalid, so discard T1
            t2_timeout = client_compute_timeout(client, self.lease_lifetime, 0.5);
            self.lease_t2 = self.lease_lifetime / 2;
    else:
        # fall back to the default timeouts
        t1_timeout = client_compute_timeout(client, self.lease_lifetime, 0.5);
        self.lease_t1 = self.lease_lifetime / 2;
        t2_timeout = client_compute_timeout(client, self.lease_lifetime, 7.0 / 8.0);
        self.lease_t2 = (self.lease_lifetime * 7) / 8;

    self.timeout_expire = GLib.timeout_add(lifetime_timeout, client_timeout_expire)     # fixme unit?

    log_dhcp_client(client, "lease expires in %s",
                    format_timespan(time_string, FORMAT_TIMESPAN_MAX, lifetime_timeout - time_now, USEC_PER_SEC));

    /* don't arm earlier timeouts if this has already expired */
    if (lifetime_timeout <= time_now)
            return 0;

    self.timeout_t2 = GLib.timeout_add(t2_timeout, client_timeout_t2)

    log_dhcp_client(client, "T2 expires in %s",
                    format_timespan(time_string, FORMAT_TIMESPAN_MAX, t2_timeout - time_now, USEC_PER_SEC));

    /* don't arm earlier timeout if this has already expired */
    if (t2_timeout <= time_now)
            return 0;

    self.timeout_t1 = GLib.timeout_add(t1_timeout, client_timeout_t1)

    log_dhcp_client(client, "T1 expires in %s",
                    format_timespan(time_string, FORMAT_TIMESPAN_MAX, t1_timeout - time_now, USEC_PER_SEC));

    return 0;
}














    def _genDiscover(self):
        dhcp_discover = (
            Ether(src=str2mac(self.client_mac), dst=self.server_mac) /
            IP(src=self.client_ip, dst=self.server_ip) /
            UDP(sport=self.client_port, dport=self.server_port) /
            BOOTP(chaddr=[self.client_mac], xid=self.client_xid) /
            DHCP(options=[
                ("message-type", "discover"),
                ("param_req_list", PARAM_REQ_LIST), 
                ("max_dhcp_size", MAX_DHCP_LEASE),
                ("client_id", self.client_mac),
                ("lease_time", LEASE_TIME),  
                ("hostname", self.hostname),
                "end"
            ])
        )
        return dhcp_discover


    def _genRequest(self):
        dhcp_req = (
            Ether(src=str2mac(self.client_mac), dst=self.server_mac) /
            IP(src=self.client_ip, dst=self.server_ip) /
            UDP(sport=self.client_port, dport=self.server_port) /
            BOOTP(chaddr=[self.client_mac], xid=self.client_xid) /
            DHCP(options=[
                ("message-type", "request"),
                ("param_req_list", PARAM_REQ_LIST),
                ("max_dhcp_size", MAX_DHCP_LEASE),
                ("client_id", self.client_mac),
                ("requested_addr", self.client_ip_offered),  # obtained from discover
                ("server_id", self.server_id),  # obtained from discover
                ("hostname", self.hostname),
                "end"
            ])
        )
        return dhcp_req



    def _genRelease(self):
        dhcp_release = (
            Ether(src=str2mac(self.client_mac), dst="ff:ff:ff:ff:ff:ff") /
            IP(src=self.client_ip, dst=self.server_ip) /
            UDP(sport=self.client_port, dport=self.server_port) /
            BOOTP(chaddr=[self.client_mac], xid=self.client_xid) /
            DHCP(options=[
                ("message-type", "release"), 
                ("server_id", self.server_id),  # obtained from discover
                ("client_id", self.client_mac),
                "end"
            ])
        )
        return dhcp_release








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

        self.dhcpClientProc = subprocess.Popen([
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











        # for debugging
#CLIENT_PORT= 8001
#SERVER_PORT= 8000
CLIENT_PORT= 68
SERVER_PORT= 67
BROADCAST_ADDR = '255.255.255.255'
META_ADDR = '0.0.0.0'
BROADCAST_MAC = 'ff:ff:ff:ff:ff:ff'

MAX_DHCP_LEASE = 1500
LEASE_TIME = 43200 # 7776000
# "subnet_mask", "router", "name_server", "domain"
PARAM_REQ_LIST = '\x01\x03\x06\x0fw\xfc'# \x1c3

INIT_STATE = 0
BOUND_STATE = 1
RENEW_STATE  = 2
REBIND_STATE = 3
REBOOT_STATE = 4
TIMEOUT_STATE = 5

RENEW_TIME_ON_LEASE = 1.0/2
REBIND_TIME_ON_LEASE = 7.0/8

class Limits:
    XID_MIN = 1
    XID_MAX = 900000000


def randomHostname(length=8, charset=None):
        charset = charset or string.ascii_uppercase + string.digits
        return ''.join(random.choice(charset) for x in range(length))


def genXid():
    return random.randint(Limits.XID_MIN, Limits.XID_MAX)



class DHCPv4Client(object):

    def __init__(self, iface,  server_port=None, client_port=None,  server_ip=None,  
                        server_mac=None, hostname=None):
        self.iface = iface
        
        self.state = INIT_STATE
        self.renew_time = 0
        self.rebind_time = 0

        self.server_port = server_port or SERVER_PORT
        self.client_port = client_port or CLIENT_PORT

        self.server_ip = server_ip or BROADCAST_ADDR
        self.server_mac = server_mac or BROADCAST_MAC

        self.client_ip = META_ADDR
        _, client_mac = get_if_raw_hwaddr(self.iface)
        self.client_mac = client_mac

        self.hostname = hostname or randomHostname()
        self.client_xid = genXid()
        
        # FIXME: when server xid is used?
        self.server_xid = None
        self.server_id = None
        self.response_server_ip = None
        self.response_server_mac = None

        self.client_ip_offered = None
        self.subnet_mask = None
        self.offered_ip = None
        self.lease_time = None
        self.router = None
        self.name_server = None
        self.domain = None
        self.options = []

        self.callbacks = {}
        self.history = []


    def __str__(self):
        return self.__repr__()

    def __repr__(self):
        return """DHCPv4 Client
        
        Interface: %sp
        Verbosity: %s
        
        Client Configuration:                |      Server
        -------------------------------------|------------------------------
        IP        =        %-20s      %-20s
        HWAddr    =        %-20s      %-20s
        
        Hostname  =        %-20s              
        MASK      =        %-20s
        
        xID       =        %-20s      %-20s
        
        
        
        DHCP Specific
        --------------------
        serverID  =        %-20s
        Options   =        %-20s
        
        
        Registered Callbacks
        --------------------
        %s
        History
        --------------------
        %s
        """ % (conf.iface, conf.verb,
               self.client_ip,
               self.server_ip,
               self.client_mac,
               self.server_mac,
               self.hostname,
               self.subnet_mask,
               self.client_xid,
               self.server_xid,
               self.server_id,
               repr(self.options),
               self.callbacks,
               self.history)

    def register_callback(self, hook, func):
        self.callbacks[hook] = func

    def exec_callback(self, hook, args):
        self.track_history("Hook:" + str(hook))
        if self.callbacks.has_key(hook):
            self.callbacks[hook]()

    def track_history(self, name=None):
        from inspect import stack
        name = name or stack()[1][3]
        self.history.append(name)



    def parseOffer(self, packet):
        print 'Parsing offer'
        print packet.show()
        self.response_server_ip =  packet[IP].src
        self.response_server_mac = packet[Ether].src
        self.server_id = packet[BOOTP].siaddr
        #FIXME: xid has to match the initial xid
        # packet[BOOTP].xid
        # FIXME: chaddr has to match client_mac
        # str2mac(packet[BOOTP].chaddr)
        # FIXME: check if yiaddr  match current client ip or requested ip
        self.client_ip_offered = packet[BOOTP].yiaddr
        
        for option in packet[DHCP].options:
            if type(option) == tuple:
                if option[0] == 'subnet_mask':
                    self.subnet_mask = option[1]
                if option[0] == 'router':
                    self.router = option[1]
                if option[0] == 'domain':
                    self.domain = option[1]
                if option[0] == 'name_server':
                    self.name_server = option[1]
                if option[0] == 'lease_time':
                    self.lease_time = option[1]

    def parseACK(self, packet):
        print "Parsing ACK"
        print packet.show()
        # FIXME: check these fields match current ones?
        #self.response_server_ip =  packet[IP].src
        #self.response_server_mac = packet[Ether].src
        #self.server_id = packet[BOOTP].siaddr
        #FIXME: xid has to match the initial xid
        # packet[BOOTP].xid
        # FIXME: chaddr has to match client_mac
        # str2mac(packet[BOOTP].chaddr)
        # FIXME: check if yiaddr  match current client ip or requested ip
        self.client_ip_offered = packet[BOOTP].yiaddr
        
        #FIXME: check these options match offered ones?
        for option in packet[DHCP].options:
            if type(option) == tuple:
                if option[0] == 'subnet_mask':
                    self.subnet_mask = option[1]
                if option[0] == 'router':
                    self.router = option[1]
                if option[0] == 'domain':
                    self.domain = option[1]
                if option[0] == 'name_server':
                    self.name_server = option[1]
                if option[0] == 'lease_time':
                    self.lease_time = option[1]

    def isOffer(self, packet):
        if DHCP in packet and DHCPTypes[packet[DHCP].options[0][1]] == 'offer':
            return True
        return False

    def isNAK(self, packet):
        if DHCP in packet and DHCPTypes[packet[DHCP].options[0][1]] == 'nak':
            return True
        return False

    def isACK(self, packet):
        if DHCP in packet and DHCPTypes[packet[DHCP].options[0][1]] == 'ack':
            return True
        return False

    def sendDiscover(self):
        packet = self.genDiscover()
        self.track_history()
        print packet.show()
        sendp(packet)
        print "Sent discover"

    def sendRequest(self):
        packet = self.genRequest()
        self.track_history()
        print packet.show()
        sendp(packet)
        print "Sent request"


    def setAddr(self):
        print "Setting address"
        #FIXME: subprocess.call to really set ip, route, nameserver
        set_ip = "ip addr add local %s netmask %s dev %s" % \
            (self.client_ip_offered,  self.subnet_mask, self.iface)
        set_route = "route add default gw %s" % self.router
        #FIXME: set nameserver with resolvconf if installed
        print set_ip
        print set_route
        #subprocess.call([set_ip])
        #subprocess.call([set_route])

    def handleResponse(self, packet):  
        print "Handling response"
        if self.isOffer(packet):
            print "Offer detected"
            self.parseOffer(packet)
            self.sendRequest()
        if self.isACK(packet):
            print "ACK detected"
            self.parseACK(packet)
            self.setAddr()
            self.state = BOUND_STATE
            self.renew_time = self.lease_time * RENEW_TIME_ON_LEASE
            self.rebind_time = self.lease_time * REBIND_TIME_ON_LEASE
            print "Sleeping for % secs." % self.renew_time
            sleep(self.renew_time)
            self.state = RENEW_STATE
            self.sendRequest()
            
        if self.isNAK(packet):
            print "NAK detected"
            # FIXME: implement

    def getResponse(self, timeout=3, tries=1):
        #FIXME: server_port is src and client_port is dst
        sniff(filter="udp and (port %s or %s)" % \
                    (self.server_port,  self.client_port),
                prn=self.handleResponse, store=0,  iface=conf.iface)