# import argparse
# import pathlib
from processor import Processor


# TODO argument parser

def main():
    # parser = argparse.ArgumentParser(description="PCAP Processor")
    # parser.add_argument('-f', '--file_path', nargs='?', const='./samples/test.pcap', type=pathlib.Path)
    # args = parser.parse_args()
    # file_path = args.file_path.as_posix()
    file_path = r'./samples/test.pcap'
    proc = Processor(file_path)
    # proc.debug_display(6)
    for i in proc.extract_conn_info():
        print(i)
    print(len(proc.extract_conn_info()))


if __name__ == "__main__":
    main()
