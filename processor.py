from scapy.all import *
from scapy.layers.inet6 import *
from scapy.layers.l2 import ARP
from collections import Counter


def get_layers(p):
    count = 0
    while True:
        lay = p.getlayer(count)
        if lay is None:
            break
        yield lay
        count += 1


class Processor:
    def __init__(self, filepath):
        self.path = filepath
        self.cap = rdpcap(self.path)

    def debug_display(self, i=int):
        ls(self.cap[i])
        # self.cap[i].show()

    def extract_ip_addr(self, ip=IP):
        list_of_ips = [p[ip].src for p in self.cap if ip in p]
        list_of_ips.extend([p[ip].dst for p in self.cap if ip in p])
        return dict(Counter(list_of_ips))

    def extract_conn_info(self, ip=IP):
        extract_list = []
        for p in self.cap:
            lays = [layer.name for layer in get_layers(p)]
            if ARP in p:
                extract_list.append({'layers': lays, 'ip_src': p[ARP].psrc, 'ip_dst': p[ARP].pdst})
            if ip in p:
                extract_list.append({'layers': lays, 'ip_src': p[ip].src, 'ip_dst': p[ip].dst})
                if TCP in p or UDP in p:
                    extract_list[-1].update({'s_port': p[ip].sport, 'd_port': p[ip].dport})
        return extract_list
