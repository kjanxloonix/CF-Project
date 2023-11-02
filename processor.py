from scapy.all import rdpcap


class Processor:
    def __init__(self, filepath):
        self.filepath = filepath

    def display_pcap(self):
        cap = rdpcap(self.filepath)
        for packet in cap:
            print(packet)
