"""Minimal userspace TCP/IP stack used to emulate firewall middleboxes.

Only the IPv4/TCP subset needed by the hping3 firewall probe tests is
implemented. Everything relies on the Python standard library and
AF_PACKET, so the suite runs inside an unprivileged user+network namespace
without tcpdump, scapy or nftables.
"""
