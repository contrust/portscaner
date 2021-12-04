import multiprocessing
from time import perf_counter as pc

from scapy.layers.inet import TCP, ICMP

from portscaner.application_protocols import ApplicationProtocols
from portscaner.service_application_protocol_detection import \
    get_service_application_protocol
from portscaner.transport_protocols import TransportProtocols
from portscaner.transport_protocols_transfers import \
    tcp_send_syn_and_recv_ack, tcp_send_rst


class PortScaner:
    def __init__(self, domain: str, timeout: float, max_threads: int,
                 ports: iter = None,
                 verbose: bool = True,
                 show_app_protocols: bool = True):
        self.domain = domain
        self.max_threads = max_threads
        self.timeout = timeout
        self.verbose = verbose
        self.show_app_protocols = show_app_protocols
        self.ports = ports if ports else set()
        self.results = {}

    def scan(self, port: int, transport_protocol: TransportProtocols):
        execution_time = 0
        if transport_protocol.value == TransportProtocols.TCP.value:
            start_time = pc()
            ack_packet = tcp_send_syn_and_recv_ack(self.domain, port,
                                                   self.timeout)
            end_time = pc()
            execution_time = end_time - start_time
            tcp_send_rst(self.domain, port, self.timeout)
            if not ack_packet or ack_packet.haslayer(ICMP) or \
                    not ack_packet.haslayer(TCP) or \
                    ack_packet.getlayer(TCP).flags != "SA":
                return
        application_protocol = \
            get_service_application_protocol(self.domain, port,
                                             transport_protocol,
                                             self.timeout)
        if transport_protocol == TransportProtocols.TCP and \
                not application_protocol:
            application_protocol = ApplicationProtocols.UNKNOWN
        if application_protocol:
            self._print_formatted_result(port, transport_protocol,
                                         application_protocol, execution_time)

    def scan_all(self):
        with multiprocessing.Pool(self.max_threads) as pool:
            pool.starmap(self.scan, self.ports)

    def _print_formatted_result(self, port: int,
                                transport_protocol: TransportProtocols,
                                application_protocol: ApplicationProtocols,
                                execution_time: float):
        str_time_in_milliseconds = f'{int(execution_time * 1000)},ms'
        str_application_protocol = application_protocol.value \
            if application_protocol.value != \
            application_protocol.UNKNOWN.value else '-'
        if self.show_app_protocols and self.verbose and \
                transport_protocol == TransportProtocols.TCP:
            print(("{:<1} " * 4).format(transport_protocol.value, port,
                                        str_time_in_milliseconds,
                                        str_application_protocol))
        elif self.verbose and transport_protocol == TransportProtocols.TCP:
            print(("{:<1} " * 3).format(transport_protocol.value, port,
                                        str_time_in_milliseconds))
        elif self.show_app_protocols:
            print(("{:<1} " * 3).format(transport_protocol.value, port,
                                        str_application_protocol))
        else:
            print(("{:<1} " * 2).format(transport_protocol.value, port))
