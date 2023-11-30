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

    def filter_packets(self, d_filter):
        try:
            pyshark.FileCapture(self.path, display_filter=d_filter, output_file=self.filter_filepath).load_packets()
            if Path(self.filter_filepath).stat().st_size == 0:
                raise Exception('Filter file is empty.')
        except Exception as e:
            print(f'An error occurred: {e}')
        else:
            self.filter_capture = rdpcap(self.filter_filepath)

    def display_filter(self, method='plain'):
        try:
            if self.filter_capture is None:
                raise Exception('Filter file is empty.')
        except Exception as e:
            print(f'An error occurred: {e}')
        else:
            if len(self.filter_capture) != 0:
                match method:
                    case 'plain':
                        for pkt in self.filter_capture:
                            print(pkt)
                    case 'hex':
                        for pkt in self.filter_capture:
                            sep_str = '='*71+'\n'
                            print(sep_str+hexdump(pkt, True), end='\n'+sep_str)
                    case _:
                        raise ValueError('Incorrect method applied.')

    def __glc_ftp(self, login_credentials, usernames, passwords):
        self.filter_packets('ftp.request.command == "USER" ||  ftp.request.command == "PASS"')
        for pkt in self.filter_capture:
            usernames.extend(rb.decode("utf-8") for rb in re.findall(rb'USER (.*?)\r\n', raw(pkt)))
            passwords.extend(rb.decode("utf-8") for rb in re.findall(rb'PASS (.*?)\r\n', raw(pkt)))
        else:
            login_credentials.append(list(set(usernames)))
            login_credentials.append(list(set(passwords)))

    def __glc_telnet(self, login_credentials, usernames, passwords):
        # TODO cleanup
        self.filter_packets('telnet.data')
        marked_index = None
        tmp = ''

        for i in range(len(self.filter_capture)):
            if raw(self.filter_capture[i])[-7:] == b'login: ':
                marked_index = i

                # TODO: extraction when one field password/username
                        # for j in range(login_pkt + 1, len(self.filter_capture)):
                        #     if (raw(self.filter_capture[j])[-2:] == b'\r\x00'
                        #             and raw(self.filter_capture[j])[62] == 21):
                        #         print(raw(self.filter_capture[j]))
                        #         z = [rb.decode("utf-8") for rb in re.findall(b'\x15...(.*?)\r\x00',
                        #                                                      raw(self.filter_capture[j]))]
                        #         print(z)

                for j in range(marked_index + 1, len(self.filter_capture)):
                    if raw(self.filter_capture[j])[-2:] == b'\r\x00':
                        usernames.append(tmp)
                        marked_index = None
                        tmp = ''
                        break
                    # Concat segmented usernames
                    tmp += (raw(self.filter_capture[j])[-1:]).decode('utf-8')

            if raw(self.filter_capture[i])[-10:] == b'Password: ':
                marked_index = i
                for j in range(marked_index + 1, len(self.filter_capture)):
                    if raw(self.filter_capture[j])[-2:] == b'\r\x00':
                        passwords.append(tmp)
                        marked_index = None
                        tmp = ''
                        break
                    # Concat segmented passwords
                    tmp += (raw(self.filter_capture[j])[-1:]).decode('utf-8')

        # clear usernames (duplicate letters)
        cl_usernames = [''.join(char1 for char1, char2 in zip(s, s[1:] + ' ') if char1 != char2) for s in usernames]

        login_credentials.append(cl_usernames)
        login_credentials.append(passwords)

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
