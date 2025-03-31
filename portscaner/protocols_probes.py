from portscaner.application_protocols import ApplicationProtocols
from portscaner.transport_protocols import TransportProtocols

_UDP_APPLICATION_PROTOCOL_PROBES = {
    ApplicationProtocols.POP3.value: [b"USER buba"],
    ApplicationProtocols.DNS.value: [
        b"\x50\x74\x01\x00\x00"
        b"\x01\x00\x00\x00\x00\x00\x00"
        b"\x06\x67\x6f\x6f\x67\x6c\x65"
        b"\x03\x63\x6f\x6d\x00\x00\x01\x00\x01"],
    ApplicationProtocols.ECHO.value: [b"echo hello"],
    ApplicationProtocols.SMTP.value: [b"HELO buba.org"],
    ApplicationProtocols.SNTP.value: [b"\x23" + bytearray(47)],
}

_TCP_APPLICATION_PROTOCOL_PROBES = {
    ApplicationProtocols.HTTP.value: [b"GET / HTTP/1.1\r\n\r\n"],
    ApplicationProtocols.POP3.value: [b"USER buba"],
    ApplicationProtocols.DNS.value: [b"\x00\x1c\x50\x74\x01\x00\x00"
                                     b"\x01\x00\x00\x00\x00\x00\x00"
                                     b"\x06\x67\x6f\x6f\x67\x6c\x65"
                                     b"\x03\x63\x6f\x6d\x00\x00\x01\x00\x01"],
    ApplicationProtocols.ECHO.value: [b"echo hello"],
    ApplicationProtocols.SMTP.value: [b"HELO buba.org"],
    ApplicationProtocols.SNTP.value: [b"\x23" + bytearray(47)],
}

APPLICATION_PROTOCOL_PROBES = {
    TransportProtocols.UDP.value: _UDP_APPLICATION_PROTOCOL_PROBES,
    TransportProtocols.TCP.value: _TCP_APPLICATION_PROTOCOL_PROBES
}
