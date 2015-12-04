#!/usr/bin/env python2

import dpkt, pcap

def str_to_hex(s):
    return ":".join("{:02x}".format(ord(c)) for c in s)

for ts, pkt in pcap.pcap():
    eth = dpkt.ethernet.Ethernet(pkt)
    if eth.type == 0x800:  # ip
        ip = eth.data
        if ip.p == 17:  # udp
            udp = ip.data
            if udp.sport == 67 and udp.dport == 68:
                print('%s' % str_to_hex(eth.src))
