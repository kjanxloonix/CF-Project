import argparse
import pathlib
from processor import Processor


def main_parser():
    parent_parser = argparse.ArgumentParser(prog='PCAP Processor CLI', description='A simple PCAP Processor')
    parent_subparsers = parent_parser.add_subparsers()

    parent_parser.add_argument('-f', '--file_path',
                               type=pathlib.Path,
                               metavar='FILEPATH',
                               required=True)
    parent_parser.add_argument('--version',
                               action='version',
                               version='%(prog)s 1.0')
    parent_parser.add_argument('-q', '--search_dns_query',
                               type=str,
                               metavar='STRING',
                               help='Search for DNS query string')
    parent_parser.add_argument('-e', '--export_connections',
                               action='store_true',
                               help='Export the connection info to CSV')
    parent_parser.add_argument('--arp_pkts',
                               action='store_true',
                               help='Specify to incorporate ARP packets')
    parent_parser.add_argument('-6', '--ip_v6',
                               action='store_true',
                               help='Specify the IPv6 usage. IPv4 by default')
    parent_parser.add_argument('-d', '--display_pakets',
                               choices=['hex', 'raw', 'plain', 'nsum'])
    parent_parser.add_argument('-i', '--ip_summary',
                               action='store_true',
                               help='Display number of occurences of IP addresses')
    parent_parser.add_argument('--export_tcp_stream',
                               type=int,
                               metavar='INDEX',
                               help='Export TCP stream data with the specified index')
    parent_parser.add_argument('--extract_ftp_files',
                               action='store_true',
                               help='Extract FTP files from PCAP')

    filtering_parser = parent_subparsers.add_parser(name="filter")
    filtering_parser.add_argument(dest='bp_filter',
                                  type=str,
                                  help='Apply Berkeley Packet Filter')
    filtering_parser.add_argument(dest='filter_display_method',
                                  type=str,
                                  choices=['hex', 'raw', 'plain'],
                                  help='Specify the display method for the filter')

    get_packet_parser = parent_subparsers.add_parser(name="packet")
    get_packet_parser.add_argument(dest='packet_index',
                                   type=int,
                                   help='The index of a packet in the PCAP file')
    get_packet_parser.add_argument(dest='packet_display_method',
                                   type=str,
                                   choices=['hex', 'raw'],
                                   help='Specify the display method for the packet')

    credentials_parser = parent_subparsers.add_parser(name="credentials")
    credentials_parser.add_argument(dest='credentials_type',
                                    choices=['telnet', 'ftp'])
    credentials_parser.add_argument('-c', '--export_credentials',
                                    action='store_true',
                                    help="Specify to export credentials to TXT")

    sessions_parser = parent_subparsers.add_parser(name="sessions")
    sessions_parser.add_argument('-a', '--sessions_print_all',
                                 action='store_true',
                                 help='Print all sessions from the PCAP')
    sessions_parser.add_argument('-d', '--sessions_display',
                                 type=str,
                                 metavar='NAME',
                                 help='Display selected session by name')
    sessions_parser.add_argument('-m', '--sessions_display_method',
                                 type=str,
                                 choices=['hex', 'raw', 'plain'],
                                 default='plain',
                                 help='Specify the display method')

    return parent_parser, parent_subparsers


def main():
    # Create parsers, parse the arguments
    parent_parser, parent_subparsers = main_parser()
    args = parent_parser.parse_args()
    # Supply filepath to the Processor
    file_path = args.file_path.as_posix()
    proc = Processor(file_path)

    # Arguments handling
    if args.search_dns_query:
        dns_qry = proc.get_dns_queries(args.search_dns_query)
        proc.display_packets(dns_qry)
    if args.export_connections:
        if args.ip_v6:
            proc.write_to_csv(ip='IPv6', arp_pkts=args.arp_pkts)
        else:
            proc.write_to_csv(arp_pkts=args.arp_pkts)
    if args.display_pakets:
        if args.display_pakets == 'nsum':
            proc.display_nsummary()
        else:
            proc.display_packets(method=args.display_pakets)
    if args.ip_summary:
        if args.ip_v6:
            print(proc.extract_ip_addr(ip='IPv6', arp_pkts=args.arp_pkts))
        else:
            print(proc.extract_ip_addr(arp_pkts=args.arp_pkts))
    if args.export_tcp_stream:
        proc.extract_tcp_stream_data(args.export_tcp_stream)
    if args.extract_ftp_files:
        proc.extract_ftp_files()
    if hasattr(args, 'bp_filter'):
        try:
            f = proc.filter_packets(args.bp_filter[0])
            if args.filter_display_method:
                proc.display_packets(f[0], args.filter_display_method)
        except Exception as e:
            print(f'An error occurred: {e}')
    if hasattr(args, 'packet_display_method') and hasattr(args, 'packet_index'):
        print(proc.get_packet(args.packet_display_method, args.packet_index))
    if hasattr(args, 'credentials_type'):
        if args.export_credentials:
            proc.credentials_to_txt(args.credentials_type)
        else:
            print(proc.get_login_credentials(args.credentials_type))
    if (hasattr(args, 'sessions_print_all') or hasattr(args, 'sessions_display')
            or hasattr(args, 'sessions_display_method')):
        if args.sessions_print_all:
            for s in proc.extract_sessions():
                print(s)
        if args.sessions_display:
            proc.display_packets(proc.extract_sessions()[args.sessions_display],
                                 args.sessions_display_method)


if __name__ == "__main__":
    main()
