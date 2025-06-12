import multiprocessing
from time import perf_counter as pc

from scapy.layers.inet import TCP

from portscaner.application_protocols import ApplicationProtocols
from portscaner.service_application_protocol_detection import \
    get_service_application_protocol
from portscaner.transport_protocols import TransportProtocols
from portscaner.transport_protocols_transfers import \
    tcp_send_syn_and_recv_ack, tcp_send_rst


class PortScaner:
    """
    A class for scanning ports on a domain.
    """
    def __init__(self, domain: str, timeout: float, max_threads: int,
                 ports: set[tuple[int, TransportProtocols]],
                 verbose: bool = True):
        """
        Initialize the PortScaner class.

        Args:
            domain (str): The domain to scan.
            timeout (float): The timeout for the scan.
            max_threads (int): The maximum number of threads to use.
            ports (set[tuple[int, TransportProtocols]]): The ports to scan.
            verbose (bool): Whether to print verbose output.
        """
        self.domain = domain
        self.max_threads = max_threads
        self.timeout = timeout
        self.verbose = verbose
        self.ports = ports
        self.results = {}

    def scan(self, port: int, transport_protocol: TransportProtocols):
        """
        Scan a single port and return the result.

        Args:
            port (tuple[int, TransportProtocols]): The port and its transport protocol to scan.

        Returns:
            None
        """
        execution_time = 0
        if transport_protocol.value == TransportProtocols.TCP.value:
            start_time = pc()
            ack_packet = tcp_send_syn_and_recv_ack(self.domain, port,
                                                   self.timeout)
            end_time = pc()
            execution_time = end_time - start_time
            tcp_send_rst(self.domain, port, self.timeout) # RST - Reset, close connection
            if not ack_packet or not ack_packet.haslayer(TCP) or \
                    ack_packet.getlayer(TCP).flags != "SA": # SA - SYN-ACK, if not, port is no longer open
                return
        application_protocol = get_service_application_protocol(self.domain, port,
                                                                transport_protocol,
                                                                self.timeout)
        if application_protocol:
            self._print_formatted_result(port, transport_protocol,
                                         application_protocol, execution_time)

    def scan_all(self):
        """
        Scan all ports and print the results to the console.
        """
        with multiprocessing.Pool(self.max_threads) as pool:
            pool.starmap(self.scan, self.ports)

    def _print_formatted_result(self, port: int,
                                transport_protocol: TransportProtocols,
                                application_protocol: ApplicationProtocols,
                                execution_time: float):
        """
        Print the port information in a formatted way to the console.

        Args:
            port (int): The port to scan.
            transport_protocol (TransportProtocols): The transport protocol to use.
            application_protocol (ApplicationProtocols): The application protocol to use.
            execution_time (float): The execution time of the scan.
        """
        str_time_in_milliseconds = f'{int(execution_time * 1000)},ms'
        str_application_protocol = application_protocol.value
        if self.verbose:
            print(("{:<1} " * 4).format(transport_protocol.value, port,
                                        str_time_in_milliseconds,
                                        str_application_protocol))
        else:
            print(("{:<1} " * 2).format(transport_protocol.value, port))
