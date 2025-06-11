import socket
from portscaner.scaner import PortScaner
from portscaner.transport_protocols import TransportProtocols
from portscaner.terminal_arguments_parsing import parse_terminal_arguments


def main():
    """
    Main function of the portscaner.
    """
    args_dict = parse_terminal_arguments()
    domain = args_dict.address
    timeout = args_dict.timeout
    max_threads = args_dict.num_threads
    ports = args_dict.ports
    verbose = args_dict.verbose
    show_app_protocols = args_dict.guess
    scaner = PortScaner(domain, timeout, max_threads, ports, verbose,
                        show_app_protocols)
    try:
        scaner.scan_all()
    except PermissionError:
        print('You should run the programme with root privileges.')
        exit(1)
    except socket.gaierror:
        print(
            f'Can not send packets to {domain}, '
            'maybe you typed wrong domain.')
        exit(1)

if __name__ == '__main__':
    main()
