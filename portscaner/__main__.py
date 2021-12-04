import argparse
import os
import socket

from portscaner.scaner import PortScaner
from portscaner.transport_protocols import TransportProtocols


def parse_terminal_arguments():
    parser = argparse.ArgumentParser(
        description="This program scans given port ranges "
                    "and prints which ports are opened. "
                    "TCP port is considered open "
                    "if it sends syn-ack packet when gets syn packet. "
                    "UDP port is considered open "
                    "if it sends any packets when gets some probes.")
    parser.add_argument(
        'address',
        type=str,
        help='ip address or domain for scanning')
    parser.add_argument(
        '--timeout',
        type=float,
        metavar='time_in_seconds',
        default=2,
        help='response timeout in seconds, 2 seconds by default'
    )
    parser.add_argument(
        '-j',
        '--num-threads',
        type=int,
        metavar='max_threads',
        default=os.cpu_count(),
        help='maximum number of threads, cpu count by default'
    )
    parser.add_argument(
        '-v',
        '--verbose',
        action='store_true',
        help='show time of getting packets from ports'
    )
    parser.add_argument(
        '-g',
        '--guess',
        action='store_true',
        help='show application protocols of services on ports'
    )
    parser.add_argument(
        'ports',
        nargs='*',
        type=parse_ports,
        help="ports for scanning in format [{tcp|udp}[/[PORT|PORT-PORT],...]]"
    )
    return parser.parse_args()


def parse_ports(string):
    split_string = string.split('/')
    protocol = split_string[0]
    if protocol not in {'tcp', 'udp'} or string.endswith('/'):
        raise argparse.ArgumentError
    if protocol == 'tcp':
        transport_protocol = TransportProtocols.TCP
    else:
        transport_protocol = TransportProtocols.UDP
    if len(split_string) == 1:
        return {(i, transport_protocol) for i in range(65536)}
    elif len(split_string) == 2:
        ports = set()
        port_ranges = split_string[1].split(',')
        for port_range in port_ranges:
            if port_range.endswith('-'):
                raise argparse.ArgumentError
            split_port_range = port_range.split('-')
            if len(split_port_range) == 1:
                if split_port_range[0].isnumeric():
                    start = int(split_port_range[0])
                    end = start
                else:
                    raise argparse.ArgumentError
            elif len(split_port_range) == 2:
                if split_port_range[0].isnumeric() and \
                        split_port_range[1].isnumeric():
                    start = int(split_port_range[0])
                    end = int(split_port_range[1])
                else:
                    raise argparse.ArgumentError
            else:
                raise argparse.ArgumentError
            if 0 <= start <= 65535 and 0 <= end <= 65535 and start <= end:
                ports.update(
                    {(i, transport_protocol) for i in range(start, end + 1)})
            else:
                raise argparse.ArgumentError
    else:
        raise argparse.ArgumentError
    return ports


def main():
    args_dict = vars(parse_terminal_arguments())
    domain = args_dict['address']
    timeout = args_dict['timeout']
    max_threads = args_dict['num_threads']
    all_ports = set()
    for ports in args_dict['ports']:
        all_ports.update(ports)
    verbose = args_dict['verbose']
    show_app_protocols = args_dict['guess']
    scaner = PortScaner(domain, timeout, max_threads, all_ports, verbose,
                        show_app_protocols)
    try:
        scaner.scan_all()
    except PermissionError:
        print('You should run the programme with root privileges.')
    except socket.gaierror:
        print(
            f'Can not send packets to {domain}, maybe you typed wrong domain.')


if __name__ == '__main__':
    main()
