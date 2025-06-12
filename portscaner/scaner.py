import multiprocessing
from time import perf_counter as pc
from scapy.layers.inet import TCP
from tqdm import tqdm

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

    def scan_port(self, port: int, transport_protocol: TransportProtocols) -> tuple[int, TransportProtocols, ApplicationProtocols, float]:
        """
        Scan a single port and return the result.
        """
        start_time = pc()
        application_protocol = self._scan_port(port, transport_protocol)
        end_time = pc()
        return port, transport_protocol, application_protocol, end_time - start_time

    def _scan_port(self, port: int, transport_protocol: TransportProtocols) -> ApplicationProtocols | None:
        """
        Scan a single port and return the result.

        Args:
            port (tuple[int, TransportProtocols]): The port and its transport protocol to scan.

        Returns:
            ApplicationProtocols | None: The application protocol if the port is open, None otherwise.
        """
        if transport_protocol.value == TransportProtocols.TCP.value:
            ack_packet = tcp_send_syn_and_recv_ack(self.domain, port,
                                                   self.timeout)
            tcp_send_rst(self.domain, port, self.timeout) # RST - Reset, close connection
            if not ack_packet or not ack_packet.haslayer(TCP) or \
                    ack_packet.getlayer(TCP).flags != "SA": # SA - SYN-ACK, if not, port is no longer open
                return None
        application_protocol = get_service_application_protocol(self.domain, port,
                                                                transport_protocol,
                                                                self.timeout)
        return application_protocol

    def scan_all(self):
        """
        Scan all ports and print the results to the console.
        """
        pbar = tqdm(total=len(self.ports), desc="Scanning ports", unit="ports")
        lock = multiprocessing.Lock()
        results = []
        def callback(result: tuple[int, TransportProtocols, ApplicationProtocols, float]) -> None:
            with lock:
                results.append(result)
                pbar.update(1)
                pbar.refresh()
        with multiprocessing.Pool(processes=self.max_threads) as p:
            start_time = pc()
            for port, transport_protocol in self.ports:
                p.apply_async(self.scan_port, (port, transport_protocol),
                              callback=callback)
            p.close()
            p.join()
        pbar.close()
        number_of_open_ports = sum(1 for _, _, application_protocol, _ in results if application_protocol)
        print(f"Number of open ports: {number_of_open_ports}/{len(self.ports)}")
        if number_of_open_ports == 0:
            return
        print()
        for port, transport_protocol, application_protocol, execution_time in results:
            if application_protocol:
                self._print_formatted_result(port, transport_protocol, application_protocol, execution_time)

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
