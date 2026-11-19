"""IPv4/TCP packet parse/build helpers (no third-party dependencies)."""

import socket
import struct


def ip_checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return (~total) & 0xFFFF


def tcp_checksum(src_ip, dst_ip, tcp_seg):
    pseudo = socket.inet_aton(src_ip) + socket.inet_aton(dst_ip) + \
        struct.pack("!BBH", 0, 6, len(tcp_seg))
    return ip_checksum(pseudo + tcp_seg)


class TcpPacket:
    def __init__(self):
        self.sport = 0
        self.dport = 0
        self.seq = 0
        self.ack = 0
        self.flags = 0
        self.window = 0
        self.urg = 0
        self.options = b""
        self.payload = b""

    @classmethod
    def parse(cls, frame):
        if len(frame) < 14 or frame[12:14] != b"\x08\x00":
            return None
        ip = frame[14:]
        ihl = (ip[0] & 0x0F) * 4
        if len(ip) < 20 or ip[9] != 6:
            return None
        total_len = struct.unpack("!H", ip[2:4])[0]
        ip = ip[:total_len]
        src = socket.inet_ntoa(ip[12:16])
        dst = socket.inet_ntoa(ip[16:20])
        seg = ip[ihl:]
        if len(seg) < 20:
            return None
        pkt = cls()
        (pkt.sport, pkt.dport, pkt.seq, pkt.ack, off_flags,
         pkt.window, _check, pkt.urg) = struct.unpack("!HHIIHHHH", seg[:20])
        data_off = (off_flags >> 12) * 4
        pkt.flags = off_flags & 0x01FF
        pkt.options = seg[20:data_off]
        pkt.payload = seg[data_off:]
        pkt.src_ip = src
        pkt.dst_ip = dst
        return pkt

    def build(self, src_mac, dst_mac):
        data_off = 5 + (len(self.options) + 3) // 4
        opts = self.options
        pad = data_off * 4 - 20 - len(opts)
        if pad:
            opts = opts + b"\x00" * pad
        off_flags = (data_off << 12) | (self.flags & 0x01FF)
        seg = struct.pack("!HHIIHHHH", self.sport, self.dport, self.seq,
                          self.ack, off_flags, self.window, 0, self.urg)
        seg += opts + self.payload
        check = tcp_checksum(self.src_ip, self.dst_ip, seg)
        seg = seg[:16] + struct.pack("!H", check) + seg[18:]

        ip_ver_ihl = 0x45
        total_len = 20 + len(seg)
        ip_hdr = struct.pack("!BBHHHBBH4s4s",
                             ip_ver_ihl, 0, total_len, 0, 0, 64, 6, 0,
                             socket.inet_aton(self.src_ip),
                             socket.inet_aton(self.dst_ip))
        ip_hdr = ip_hdr[:10] + \
            struct.pack("!H", ip_checksum(ip_hdr)) + ip_hdr[12:]
        return dst_mac + src_mac + b"\x08\x00" + ip_hdr + seg


def iter_tcp_options(raw):
    """Yield (kind, value_bytes) tuples from a raw TCP option block."""
    i = 0
    while i < len(raw):
        kind = raw[i]
        if kind == 0:  # EOL
            return
        if kind == 1:  # NOP
            i += 1
            continue
        if i + 1 >= len(raw):
            return
        length = raw[i + 1]
        if length < 2 or i + length > len(raw):
            return
        yield kind, raw[i + 2:i + length]
        i += length


def find_option(raw, wanted_kind):
    for kind, value in iter_tcp_options(raw):
        if kind == wanted_kind:
            return value
    return None
