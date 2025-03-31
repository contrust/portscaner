# portscaner

## Warning

The scapy module requires root privileges to bypass the OS's standard networking stack.

## Install

```sh
sudo pip install .
```

## Usage
```sh
sudo python3 -m portscaner [OPTIONS] IP_ADDRESS [{tcp|udp}[/[PORT|PORT-PORT],...]]...
```

## Features

* UDP scanning by sending some packets of application protocols
* TCP scanning by sending TCP SYN with scapy module
* Multithreading implementation with ThreadPool

## Options

| Option | Description |
| --- | --- |
| -h | Show help message |
| -j n | Use n threads for the thread pool |
| --timeout n | Set port connection timeout to n seconds |
| -g  | Show guessed protocol used on a port |
| -v | Show port response time |

## Author

**Artyom Borisov**
