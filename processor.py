from scapy.all import *
from scapy.layers.inet6 import *
from scapy.layers.l2 import ARP
from collections import Counter
import pyshark
from time import strftime
import tempfile
from os import unlink

# TODO library cleanup, error handling


class Processor:
    def __init__(self, filepath):
        self.path = filepath
        self.capture = rdpcap(self.path)
        self.filter_tempfile = tempfile.NamedTemporaryFile(prefix='filter-' + strftime("%Y%m%d%H%M%S") + '-',
                                                           suffix='.pcap', delete=False)
        self.filter_filepath = self.filter_tempfile.name
        self.filter_capture = None

    def __del__(self):
        self.filter_tempfile.close()
        unlink(self.filter_filepath)

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
        ls(self.capture[i])
        # self.cap[i].show()

    def extract_ip_addr(self, ip='IP'):
        list_of_ips = [p[ip].src for p in self.capture if ip in p]
        list_of_ips.extend([p[ip].dst for p in self.capture if ip in p])
        return dict(Counter(list_of_ips))

    def extract_conn_info(self, ip='IP'):
        extract_list = []
        for p in self.capture:
            lays = [layer.name for layer in self.__get_layers(p)]
            if ARP in p:
                extract_list.append({'arr_time': p.time, 'layers': lays, 'ip_src': p[ARP].psrc,
                                     'ip_dst': p[ARP].pdst, 'mac_src': p[ARP].hwsrc, 'mac_dst': p[ARP].hwdst})
            if ip in p:
                if TCP in p or UDP in p:
                    extract_list.append(
                        {'arr_time': p.time, 'layers': lays, 'ip_src': p[ip].src, 'ip_dst': p[ip].dst,
                         's_port': p[ip].sport, 'd_port': p[ip].dport, 'mac_src': p[ip].src, 'mac_dst': p[ip].dst})
                else:
                    extract_list.append({'arr_time': p.time, 'layers': lays,
                                         'ip_src': p[ip].src, 'ip_dst': p[ip].dst,
                                         'mac_src': p[ip].src, 'mac_dst': p[ip].dst})
        return extract_list

    def extract_sessions(self):
        return self.capture.sessions()

    def get_packet(self, method, i=0):
        p = self.capture[i]
        match method:
            case 'hex':
                return hexdump(p, True)
            case 'raw':
                return raw(p)

    def filter_packets(self, d_filter):
        try:
            pyshark.FileCapture(self.path, display_filter=d_filter, output_file=self.filter_filepath).load_packets()
            self.filter_capture = rdpcap(self.filter_filepath)
        except Exception as e:
            e.add_note('Filter file does not exist.')
            e.add_note('Apply correct display filter and try again.')
            raise

    def display_filter(self):
        for pkt in self.filter_capture:
            print(pkt)
