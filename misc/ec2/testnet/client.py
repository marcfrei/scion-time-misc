#!/usr/bin/python3
# Minimal client implementation with support for the interleaved mode

# Based on https://github.com/mlichvar/draft-ntp-interleaved-modes/
# by Miroslav Lichvar

import random
import socket
import struct
import sys
import time

class NtpClient:
    def __init__(self, hostname, poll):
        self.hostname = hostname
        self.poll_interval = 2**poll
        self.max_missed_responses = 4

    def read_clock(self):
        return int((time.time() + 0x83aa7e80) * 4294967296)

    def make_request(self):
        self.missed_responses += 1

        self.cookie_basic = random.getrandbits(64)
        self.cookie_interleaved = random.getrandbits(64)

        # Make sure the receive and transmit timestamps are different
        while self.cookie_interleaved == self.cookie_basic:
            self.cookie_interleaved = random.getrandbits(64)

        # Do not make an interleaved request if too many responses were missed
        if self.missed_responses <= self.max_missed_responses:
            origin_ts = self.prev_server_receive
            receive_ts = self.cookie_interleaved
        else:
            origin_ts = 0
            receive_ts = 0
        transmit_ts = self.cookie_basic

        # print("Request:  org={:016x} rx={:016x} tx={:016x}".
        #       format(origin_ts, receive_ts, transmit_ts))

        return struct.pack('!BBbbIIIQQQQ', 0xe3, 0, 0, 32, 0, 0, 0, 0,
                           origin_ts, receive_ts, transmit_ts)

    def process_response(self, response, client_transmit, client_receive):
        if len(response) < 48:
            return False

        # Ignore duplicates
        if self.missed_responses == 0:
            return False

        (_, _, _, _, _, _, _, _, origin_ts, receive_ts, transmit_ts) = \
                struct.unpack('!BBbbIIIQQQQ', response[:48])

        # print("Response: org={:016x} rx={:016x} tx={:016x}".
        #         format(origin_ts, receive_ts, transmit_ts))

        if origin_ts == self.cookie_interleaved:
            print("interleaved mode: ", end="")
            T1 = self.prev_client_transmit
            T2 = self.prev_server_receive
            T3 = transmit_ts
            T4 = self.prev_client_receive
        elif origin_ts == self.cookie_basic:
            print("basic mode: ", end="")
            T1 = client_transmit
            T2 = receive_ts
            T3 = transmit_ts
            T4 = client_receive
        else:
            print("invalid response")
            return False

        offset = 0.5 * ((T2 - T1) + (T3 - T4))
        delay = (T4 - T1) - (T3 - T2)

        print("offset={:+.9f} delay={:.9f}".format(offset / 2.0**32, delay / 2.0**32))

        # Update client state
        self.prev_client_transmit = client_transmit
        self.prev_client_receive = client_receive
        self.prev_server_receive = receive_ts
        self.missed_responses = 0

    def run(self):
        family, _, _, _, address = socket.getaddrinfo(self.hostname, 123)[0]
        sock = socket.socket(family, socket.SOCK_DGRAM)
        sock.connect(address)

        # Force the first request to be in the basic mode
        self.missed_responses = self.max_missed_responses

        while True:
            request = self.make_request()
            sock.send(request)
            # This should be the actual transmit timestamp of the request
            transmit_ts = self.read_clock()

            next_poll = time.monotonic() + self.poll_interval

            while True:
                timeout = next_poll - time.monotonic()
                if timeout < 0:
                    break;

                sock.settimeout(timeout)

                try:
                    response = sock.recv(1024)
                except Exception:
                    continue

                receive_ts = self.read_clock()
                self.process_response(response, transmit_ts, receive_ts)

        sock.close()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: {} HOSTNAME".format(sys.argv[0]))
        sys.exit(1)

    client = NtpClient(sys.argv[1], 2)
    client.run()
