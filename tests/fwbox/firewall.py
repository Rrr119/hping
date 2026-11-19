"""Firewall/middlebox emulator.

Runs on the veth peer of the hping instance and answers TCP packets while
applying one of three configurable middlebox policies:

  passthrough  RFC 1323 compliant host: echoes the received TSval in TSecr
               and preserves every option.
  rewrite      rewrites the timestamp echo to a fixed bogus value,
               emulating a firewall that normalizes/zeroes timestamps.
  strip        removes the TCP timestamp option (and all other options)
               from its reply, emulating an option-stripping firewall.
"""

import argparse
import socket
import struct
import time

from .pkt import TcpPacket, find_option

TCPOPT_TIMESTAMP = 8
TH_SYN = 0x02
TH_ACK = 0x10


def reply_for(req, mode, src_ip=None):
    resp = TcpPacket()
    # swap addresses/ports
    resp.sport = req.dport
    resp.dport = req.sport
    resp.src_ip = src_ip if src_ip else req.dst_ip
    resp.dst_ip = req.src_ip
    resp.seq = 0x1000
    resp.ack = (req.seq + 1) & 0xFFFFFFFF
    resp.flags = TH_SYN | TH_ACK
    resp.window = 64240

    ts_value = find_option(req.options, TCPOPT_TIMESTAMP)
    if ts_value is None or mode == "strip":
        resp.options = b""
        return resp

    peer_tsval = ts_value[:4]
    if mode == "rewrite":
        echoed = struct.pack("!I", 0xDEADBEEF)
    elif mode == "passthrough":
        echoed = peer_tsval
    else:
        raise ValueError("unknown mode %r" % mode)

    own_ts = struct.pack("!I", int(time.time()) & 0xFFFFFFFF)
    # NOP,NOP prefix keeps the 10 byte option 4-byte aligned, like hping.
    resp.options = b"\x01\x01\x08\x0a" + own_ts + echoed
    return resp


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("interface")
    parser.add_argument("mode",
                        choices=["passthrough", "rewrite", "strip"])
    parser.add_argument("--count", type=int, default=1)
    parser.add_argument("--src-ip", default=None,
                        help="source IP to answer from (virtual middlebox IP)")
    args = parser.parse_args()

    # ETH_P_ALL: see fwbox/sniff.py for the userns protocol rationale.
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                         socket.htons(0x0003))
    sock.bind((args.interface, 0))
    src_mac = sock.getsockname()[4]

    answered = 0
    deadline = time.time() + 15
    while answered < args.count and time.time() < deadline:
        sock.settimeout(max(0.1, deadline - time.time()))
        try:
            frame, _meta = sock.recvfrom(65535)
        except socket.timeout:
            break
        req = TcpPacket.parse(frame)
        if req is None or not (req.flags & TH_SYN):
            continue
        dst_mac = frame[6:12]
        resp = reply_for(req, args.mode, args.src_ip)
        sock.send(resp.build(src_mac, dst_mac))
        answered += 1

    print("firewall:%s answered=%d" % (args.mode, answered))


if __name__ == "__main__":
    main()
