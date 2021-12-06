import argparse
import ipaddress
import os
from functools import partial

from portscaner.transport_protocols import TransportProtocols


def parse_terminal_arguments():
    parser = argparse.ArgumentParser(
        description="This program scans given port ranges "
                    "and prints which ports are opened. "
                    "TCP port is considered open "
                    "if it sends syn-ack packet when gets syn packet. "
                    "UDP port is considered open "
                    "if it sends any packets when gets some probe packets.")
    parser.add_argument(
        'ip_address',
        type=_string_ipv4_address,
        help='ipv4 address for scanning')
    parser.add_argument(
        'ports',
        nargs='*',
        type=_parse_ports,
        help="ports for scanning in format [{tcp|udp}[/[PORT|PORT-PORT],...]]"
    )
    parser.add_argument(
        '-j',
        '--num-threads',
        type=partial(_positive_number, number_type=int),
        metavar='max_threads',
        default=os.cpu_count(),
        help='maximum number of threads, cpu count by default'
    )
    parser.add_argument(
        '--timeout',
        type=partial(_positive_number, number_type=float),
        metavar='time_in_seconds',
        default=2,
        help='response timeout in seconds, 2 seconds by default'
    )
    parser.add_argument(
        '-g',
        '--guess',
        action='store_true',
        help='show application protocols of services on ports'
    )
    parser.add_argument(
        '-v',
        '--verbose',
        action='store_true',
        help='show time of getting packets from ports'
    )
    return parser.parse_args()


def _string_ipv4_address(string):
    try:
        ipaddress.IPv4Network(string)
        return string
    except ipaddress.AddressValueError:
        raise argparse.ArgumentTypeError(f"{string} is not an ipv4 address.")


def _positive_number(string, number_type):
    try:
        number = number_type(string)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f'Can not cast {string} to {number_type}.')
    if number > 0:
        return number
    else:
        raise argparse.ArgumentTypeError(f"{string} is not positive number.")


def _parse_ports(string):
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
