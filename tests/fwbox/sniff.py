"""Capture hping's outgoing TCP packets and report their option layout.

Used by the wire-format test to prove --tcp-option reaches the wire
unchanged, with correct NOP/EOL padding and data offset.
"""

import argparse
import socket
import time

from .pkt import TcpPacket, iter_tcp_options


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("interface")
    parser.add_argument("--count", type=int, default=1)
    parser.add_argument("--seconds", type=float, default=10.0)
    args = parser.parse_args()

    # ETH_P_ALL is required inside an unprivileged user namespace: binding a
    # specific ethertype there delivers no frames, so we filter IPv4/TCP
    # ourselves in TcpPacket.parse.
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                         socket.htons(0x0003))
    sock.bind((args.interface, 0))

    seen = 0
    deadline = time.time() + args.seconds
    while seen < args.count and time.time() < deadline:
        sock.settimeout(max(0.1, deadline - time.time()))
        try:
            frame, _meta = sock.recvfrom(65535)
        except socket.timeout:
            break
        pkt = TcpPacket.parse(frame)
        if pkt is None:
            continue
        seen += 1
        data_off = 5 + (len(pkt.options) + 3) // 4
        print("sport=%d dport=%d flags=0x%03x dataoff=%d optlen=%d opts=%s" % (
            pkt.sport, pkt.dport, pkt.flags, data_off, len(pkt.options),
            pkt.options.hex()))
        for kind, value in iter_tcp_options(pkt.options):
            print("  kind=%d len=%d value=%s" %
                  (kind, len(value) + 2, value.hex()))

    raise SystemExit(0 if seen == args.count else 1)


if __name__ == "__main__":
    main()
