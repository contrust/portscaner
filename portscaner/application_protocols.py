from enum import Enum


class ApplicationProtocols(Enum):
    HTTP = 'HTTP'
    DNS = 'DNS'
    ECHO = 'ECHO'
    SSH = 'SSH'
    UNKNOWN = 'UNKNOWN'
