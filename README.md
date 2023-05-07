# C++ Packet Analyzer

This project is a C++ packet analyzer that allows you to analyze network packets and view detailed information about each packet. The analyzer utilizes the `libpcap` library for capturing and processing packets, and `ncurses` library for interactive output and user input.

## Table of Contents

-   [Prerequisites](#prerequisites)
-   [Usage](#usage)
-   [Analyzed Packet Details](#analyzed-packet-details)
    -   [Ethernet Header](#ethernet-header)
    -   [IP Protocol (IPv4)](#ip-protocol-ipv4)
    -   [IP Protocol (IPv6)](#ip-protocol-ipv6)
    -   [TCP Header Information](#tcp-header-information)
    -   [UDP Header Information](#udp-header-information)
    -   [ICMPv4 Packet Information](#icmpv4-packet-information)
    -   [HTTP Packet](#http-packet)
    -   [HTTPS Packet](#https-packet)
    -   [DNS Packet](#dns-packet)
-   [Contributions](#contributions)
-   [License](#license)

## Prerequisites

Before running the packet analyzer, make sure you have the following dependencies installed on your system:

-   libpcap
-   ncurses

## Usage

To install the library used in program:

```shell
make install
```

To built the project:
To install the library used in program:

```shell
make
```

To start the packet analyzer, open a terminal and run the following command with administrative privileges:

```shell
sudo program fileName.pcap
```

If the specified `fileName.pcap` exists, the program will display the analyzed details of each packet in the file. If the file does not exist, the program will prompt you to select the interface you want to capture packets from. Pressing `q` will start capturing packets and write them to the specified `fileName.pcap` file.

## Analyzed Packet Details

For each packet analyzed by the program, the following information is displayed:

#### Ethernet Header

This section provides information about the Ethernet header of the packet.

<ethernet_header_info>

#### IP Protocol (IPv4)

This section provides information about the IPv4 header of the packet.

<ip_header_info>

#### IP Protocol (IPv6)

This section provides information about the IPv6 header of the packet.

<arp_header_info>

#### TCP Header Information

This section provides information about the TCP header of the packet.

<tcp_header_info>

#### UDP Header Information

This section provides information about the UDP header of the packet.

<udp_header_info>

#### ICMPv4 Packet Information

This section provides information about the ICMPv4 packet.

<icmpv4_packet_info>

#### HTTP Packet

This section provides information about the HTTP packet.

<http_packet_info>

#### HTTPS Packet

This section provides information about the HTTPS packet.

<https_packet_info>

#### DNS Packet

This section provides information about the DNS packet.

<dns_packet_info>

## Contributions

Contributions to this project are welcome. If you find any issues or have suggestions for improvement, please feel free to submit a pull request or open an issue on the project's GitHub repository.

## License

This project is licensed under the MIT License. See the LICENSE file for more details.
