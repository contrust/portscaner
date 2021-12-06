# portscaner

## Install

```sh
sudo pip install .
```

## Usage
```sh
sudo portscan [OPTIONS] IP_ADDRESS [{tcp|udp}[/[PORT|PORT-PORT],...]]...
```
or
```sh
sudo python3 -m portscaner [OPTIONS] IP_ADDRESS [{tcp|udp}[/[PORT|PORT-PORT],...]]...
```

## Features

* UDP scanning by sending some packets of application protocols
* TCP scanning by sending TCP SYN with scapy module
* Multithreading implementation with ThreadPool
* '-v' option to show time of receiving tcp packets
* '-j' option to set max number of threads
* '-g' option to show application protocol of service: HTTP, DNS, ECHO or SSH.
## Author

**Artyom Borisov**
