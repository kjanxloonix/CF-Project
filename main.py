import argparse
import pathlib

from processor import Processor

# TODO argument parser
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PCAP Processor")
    parser.add_argument('-f', '--file_path', nargs='?', const='./samples/test.pcap', type=pathlib.Path)
    args = parser.parse_args()
    file_path = args.file_path.as_posix()
else:
    file_path = './samples/test.pcap'

Processor(file_path).display_pcap()
