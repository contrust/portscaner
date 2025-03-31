# portscaner

## Warning

The scapy module requires root privileges to bypass the OS's standard networking stack.

## Install

```sh
sudo pip3 install .
```

## Usage
```sh
sudo python3 -m portscaner [OPTIONS] IP_ADDRESS [{tcp|udp}[/[PORT|PORT-PORT],...]]...
```

## Features

* UDP scanning by sending some packets of application protocols
* TCP scanning by sending TCP SYN with scapy module
* Multithreading implementation with ThreadPool
* Some popular application protocols detection

## Options

| Option | Description |
| --- | --- |
| -h | Show help message |
| -j n | Use n threads for the thread pool |
| --timeout n | Set port connection timeout to n seconds |
| -g  | Show guessed protocol used on a port |
| -v | Show port response time |

## Examples

### TCP range scan

```sh
sudo python3.10 -m portscaner -g -j 100 google.com tcp/1-1000
```

```sh
TCP 80 HTTP 
TCP 443 - 
```

### TCP specific port scan
```sh
sudo python3.10 -m portscaner -g -j 1 google.com tcp/80 
```

```sh
TCP 80 HTTP 
```

### TCP multiple specific ports scan

```sh
sudo python3.10 -m portscaner -g -j 1 google.com tcp/80,443
```

```sh
TCP 80 HTTP 
TCP 443 - 
```

### UDP DNS example

```sh
sudo python3.10 -m portscaner -g -j 100 8.8.8.8 udp/1-1000
```

```sh
UDP 53 DNS 
UDP 443 - 
```

### UDP SNTP example
```sh
sudo python3.10 -m portscaner -g -j 100 --timeout 0.5 ntp1.net.berkeley.edu udp/1-1000
```

```sh
UDP 123 SNTP 
```

### TCP POP3 example

```sh
sudo python3.10 -m portscaner -g -j 100 --timeout 0.5 mail.comcast.net tcp/1-1000
```

```sh
TCP 995 - 
TCP 993 - 
TCP 143 - 
TCP 110 POP3 
```

### TCP SMTP example
```sh
sudo python3.10 -m portscaner -g -j 100 --timeout 0.5 smtp.comcast.net tcp/1-1000
```

```sh
TCP 465 - 
TCP 25 - 
TCP 587 SMTP 
```
### TCP SSH example
```sh
sudo python3.10 -m portscaner -g -j 100 --timeout 0.5 umt.imm.uran.ru tcp/1-1000
```

```sh
TCP 443 HTTP 
TCP 22 SSH 
TCP 80 HTTP 
```

## Author

**Artyom Borisov**
