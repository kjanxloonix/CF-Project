import argparse
import pathlib
from processor import Processor


# TODO argument parser

def main():
    parser = argparse.ArgumentParser(description="PCAP Processor")
    parser.add_argument('-f', '--file_path', nargs='?',
                        const=r"./samples/TELNET.pcapng", type=pathlib.Path)
    args = parser.parse_args()
    file_path = args.file_path.as_posix()
    proc = Processor(file_path)

    # # EXAMPLES
    # print(proc.extract_sessions())
    # print(proc.extract_conn_info())
    # proc.display_nsummary()
    # print(proc.extract_ip_addr())
    # proc.get_packet('raw')
    print(proc.get_login_credentials('ftp'))
    print(proc.get_login_credentials('telnet'))
    # # firefox.settings.services.mozilla.com
    # dns_qry = proc.get_dns_queries('example.com')
    # proc.display_packets(dns_qry)


if __name__ == "__main__":
    main()
