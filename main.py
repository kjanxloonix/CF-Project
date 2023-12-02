import argparse
import pathlib
from processor import Processor


# TODO argument parser

def main():
    parser = argparse.ArgumentParser(description="PCAP Processor")
    parser.add_argument('-f', '--file_path', nargs='?', const=r"./samples/TELNET.pcapng", type=pathlib.Path) #  cm4116_telnet.cap
    args = parser.parse_args()
    file_path = args.file_path.as_posix()
    proc = Processor(file_path)
    # # EXAMPLES
    # proc.extract_sessions()
    # print(proc.extract_conn_info())
    # proc.display_nsummary()
    # print(proc.extract_ip_addr())
    # proc.get_packet('raw')
    # print(proc.get_login_credentials('telnet'))
    # # firefox.settings.services.mozilla.com
    # for i in proc.get_dns_queries('firefox.settings.services.mozilla.com'):
    #     print(i)
    proc.get_tcp_streams()


if __name__ == "__main__":
    main()
