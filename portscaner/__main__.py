import socket
from portscaner.scaner import PortScaner
from portscaner.terminal_arguments_parsing import parse_terminal_arguments


def main():
    args_dict = vars(parse_terminal_arguments())
    domain = args_dict['ip_address']
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
