from scapy.all import *
from scapy.layers.inet6 import *
from scapy.layers.l2 import ARP
from collections import Counter
# import pyshark


class Processor:
    def __init__(self, filepath):
        self.path = filepath
        self.cap = rdpcap(self.path)

    def __get_layers(self, pkt):
        count = 0
        while True:
            layer = pkt.getlayer(count)
            if layer is None:
                break
            yield layer
            count += 1

    def debug_display(self, i=int):
        """
        TODO: marked for removal in the final build
        """
        ls(self.cap[i])
        # self.cap[i].show()

    def extract_ip_addr(self, ip='IP'):
        list_of_ips = [p[ip].src for p in self.cap if ip in p]
        list_of_ips.extend([p[ip].dst for p in self.cap if ip in p])
        return dict(Counter(list_of_ips))

    def extract_conn_info(self, ip='IP'):
        extract_list = []
        for p in self.cap:
            lays = [layer.name for layer in self.__get_layers(p)]
            if ARP in p:
                extract_list.append({'arr_time': p.time, 'layers': lays,
                                     'ip_src': p[ARP].psrc, 'ip_dst': p[ARP].pdst})
            if ip in p:
                if TCP in p or UDP in p:
                    extract_list.append(
                        {'arr_time': p.time, 'layers': lays, 'ip_src': p[ip].src,
                         'ip_dst': p[ip].dst, 's_port': p[ip].sport, 'd_port': p[ip].dport})
                else:
                    extract_list.append({'arr_time': p.time, 'layers': lays,
                                         'ip_src': p[ip].src, 'ip_dst': p[ip].dst})
        return extract_list

    def extract_sessions(self):
        return self.cap.sessions()

    def get_packet(self, method, i=0):
        p = self.cap[i]
        match method:
            case 'hex':
                return hexdump(p, True)
            case 'raw':
                return raw(p)

    def filter_packets(self):
        """"
        TODO implement packet filtering
        """
        pass
    #     # s = sniff(offline=self.path, filter = "ip and host 192.168.0.1")
    #     # print(s)
    #     filtered_cap = pyshark.FileCapture(self.path, display_filter='arp')
    #     for i in filtered_cap:
    #         print(i)
