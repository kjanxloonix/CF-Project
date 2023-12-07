from scapy.all import *
from scapy.layers.inet6 import *
from scapy.layers.l2 import ARP
from collections import Counter
import pyshark
from time import strftime
import tempfile
from os import unlink
from pathlib import Path
import re


# TODO library & code cleanup


class Processor:
    def __init__(self, filepath):
        try:
            Path(filepath).resolve(strict=True)
        except FileNotFoundError:
            raise
        else:
            self.path = filepath
            self.capture = rdpcap(self.path)
            self.filter_tempfiles = []
            self.filter_filepaths = []
            self.tcp_streams = []

    def __del__(self):
        for i in range(len(self.filter_tempfiles)):
            try:
                self.filter_tempfiles[i].close()
                unlink(self.filter_tempfiles[i].name)
            except FileNotFoundError as e:
                e.add_note("An error occured: No file to close.")
                e.add_note("Check temporary directory for the orphaned filter files.")
                raise

    @staticmethod
    def __get_layers(pkt):
        count = 0
        while True:
            layer = pkt.getlayer(count)
            if layer is None:
                break
            yield layer
            count += 1

    @staticmethod
    def __glc_telusr_handler(stream, usernames):
        for i in range(len(stream)):
            if b'login: ' in stream[i][Raw].load:
                counter = 0
                tmp = b''
                for j in range(i + 1, len(stream)):
                    counter += 1
                    if b'\r\x00' in stream[j][Raw].load:
                        tmp += stream[j][Raw].load
                        if counter > 1:
                            usernames.append(''.join(tmp[:-2].decode('utf-8')[i]
                                                     for i in range(len(tmp[:-2].decode('utf-8'))) if i == 0 or
                                                     tmp[:-2].decode('utf-8')[i] != tmp[:-2].decode('utf-8')[i - 1]))
                        else:
                            usernames.append(tmp[:-2].decode('utf-8'))
                        break
                    else:
                        tmp += stream[j][Raw].load

    @staticmethod
    def __glc_telpass_handler(stream, passwords):
        for i in range(len(stream)):
            if b'Password: ' in stream[i][Raw].load:
                tmp = b''
                for j in range(i + 1, len(stream)):
                    if b'\r\x00' in stream[j][Raw].load:
                        tmp += stream[j][Raw].load
                        passwords.append(tmp[:-2].decode('utf-8'))
                        break
                    else:
                        tmp += stream[j][Raw].load

    def has_tcp_streams(self):
        return True if len(self.tcp_streams) > 0 else False

    def get_tcp_streams(self):
        if len(self.tcp_streams) != 0:
            return self.tcp_streams
        else:
            counter = 0
            while True:
                self.tcp_streams.append(self.filter_packets("tcp.stream eq " + str(counter)))
                counter += 1
                if len(self.tcp_streams[-1][0]) == 0:
                    self.tcp_streams.pop()
                    break
            return self.tcp_streams

    def display_nsummary(self):
        self.capture.nsummary()

    def extract_ip_addr(self, ip='IP', arp_pkts=False):
        match ip:
            case 'IP' | 'IPv6':
                list_of_ips = [p[ip].src for p in self.capture if ip in p]
                list_of_ips.extend([p[ip].dst for p in self.capture if ip in p])
            case _:
                raise ValueError('Incorrect protocol applied.')
        if arp_pkts is True:
            list_of_ips.extend([p[ARP].psrc for p in self.capture if ARP in p])
            list_of_ips.extend([p[ARP].pdst for p in self.capture if ARP in p])
        return dict(Counter(list_of_ips))

    def extract_conn_info(self, ip='IP', arp_pkts=True):
        extract_list = []
        for p in self.capture:
            lays = [layer.name for layer in self.__get_layers(p)]
            if ARP in p and arp_pkts is True:
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
        try:
            pkt = self.capture[i]
            match method:
                case 'hex':
                    return hexdump(pkt, True)
                case 'raw':
                    return raw(pkt)
                case _:
                    raise ValueError('Incorrect method applied.')
        except Exception as e:
            print(f'An error occurred: {e}')

    def filter_packets(self, d_filter, filter_path=None):
        try:
            if filter_path is None:
                filter_path = self.path
            self.filter_tempfiles.append(tempfile.NamedTemporaryFile(prefix='filter-' + strftime("%Y%m%d%H%M%S") + '-',
                                                                     suffix='.pcap', delete=False))
            self.filter_filepaths.append(self.filter_tempfiles[-1].name)
            pyshark.FileCapture(filter_path, display_filter=d_filter,
                                output_file=self.filter_filepaths[-1]).load_packets()
            if Path(self.filter_filepaths[-1]).stat().st_size == 0:  # Empty filter file handling
                self.filter_tempfiles[-1].close()
                unlink(self.filter_tempfiles[-1].name)
                self.filter_tempfiles.pop()
                self.filter_filepaths.pop()
                raise Exception('Filter file is empty.')
            else:
                return rdpcap(self.filter_filepaths[-1]), self.filter_filepaths[-1]
        except Exception as e:
            print(f'An error occurred: {e}')

    def display_packets(self, cap=None, method='plain'):
        try:
            cap = self.capture if cap is None else cap
            match method:
                case 'plain':
                    for pkt in cap:
                        print(pkt)
                case 'hex':
                    for pkt in cap:
                        sep_str = '=' * 71 + '\n'
                        print(sep_str + hexdump(pkt, True), end='\n' + sep_str)
                case 'raw':
                    for pkt in cap:
                        print(raw(pkt))
                case _:
                    raise ValueError('Incorrect method applied.')
        except Exception as e:
            print(f'An error occurred: {e}')

    def __glc_ftp(self, login_credentials, usernames, passwords):
        ftp_filter = self.filter_packets('ftp.request.command == "USER" ||  ftp.request.command == "PASS"')[0]
        for pkt in ftp_filter:
            usernames.extend(rb.decode("utf-8") for rb in re.findall(rb'USER (.*?)\r\n', raw(pkt)))
            passwords.extend(rb.decode("utf-8") for rb in re.findall(rb'PASS (.*?)\r\n', raw(pkt)))
        else:
            login_credentials.append(list(set(usernames)))
            login_credentials.append(list(set(passwords)))

    def __glc_telnet(self, login_credentials, usernames, passwords):
        if not self.has_tcp_streams():
            self.get_tcp_streams()

        telnet_filter = []
        for stream, path in self.tcp_streams:
            telnet_filter.append(self.filter_packets('telnet', path))

        for stream, path in telnet_filter:
            self.__glc_telusr_handler(stream, usernames)
            self.__glc_telpass_handler(stream, passwords)

        login_credentials.append(list(set(usernames)))
        login_credentials.append(list(set(passwords)))

    def get_login_credentials(self, proto):
        login_credentials, usernames, passwords = [], [], []
        match proto:
            case 'ftp':
                self.__glc_ftp(login_credentials, usernames, passwords)
            case 'telnet':
                self.__glc_telnet(login_credentials, usernames, passwords)
            case _:
                raise ValueError('Incorrect protocol applied.')
        return proto, login_credentials

    def get_dns_queries(self, dns_qry_name=''):
        return self.filter_packets('dns.qry.name=="' + str(dns_qry_name) + '"')[0]
