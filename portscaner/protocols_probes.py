from application_protocols import ApplicationProtocols
from transport_protocols import TransportProtocols

_UDP_APPLICATION_PROTOCOL_PROBES = {
    ApplicationProtocols.HTTP.value: [b"GET / HTTP/1.1"],
    ApplicationProtocols.DNS.value: [
        b"\xbb\xe7\x01\x00\x00\x01\x00\x00\x00\x00\x00\x01\x06\x67\x69\x74"
        b"\x68\x75\x62\x03\x63\x6f\x6d\x00\x00\x01\x00\x01\x00\x00\x29\x02"
        b"\x00\x00\x00\x00\x00\x00\x00"],
    ApplicationProtocols.ECHO.value: [b"echo hello"]
}

_TCP_APPLICATION_PROTOCOL_PROBES = {
    ApplicationProtocols.HTTP.value: [b"wrong request to get bad response"],
    ApplicationProtocols.DNS.value: [b"\x00\x1c\x50\x74\x01\x00\x00"
                               b"\x01\x00\x00\x00\x00\x00\x00"
                               b"\x06\x67\x6f\x6f\x67\x6c\x65"
                               b"\x03\x63\x6f\x6d\x00\x00\x01\x00\x01"],
    ApplicationProtocols.ECHO.value: [b"echo hello"]
}

APPLICATION_PROTOCOL_PROBES = {
    TransportProtocols.UDP.value: _UDP_APPLICATION_PROTOCOL_PROBES,
    TransportProtocols.TCP.value: _TCP_APPLICATION_PROTOCOL_PROBES
}