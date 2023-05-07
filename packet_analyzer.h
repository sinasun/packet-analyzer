#ifndef PACKET_ANALYZER_H
#define PACKET_ANALYZER_H

#include <iostream>
#include <stdio.h>
#include <string>
#include <ncurses.h>
#include <pcap.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/if_ether.h>

class Analyzer
{
public:
    Analyzer(std::string fileName);
    static void packet_handler(unsigned char *user_data, const struct pcap_pkthdr *packet_header, const unsigned char *packet_data);

    static void handle_dns_packet(const u_char *packet_data);
    static void handle_arp_packet(const u_char *packet_data);
    static void handle_tcp_packet(const u_char *packet_data);
    static void handle_udp_packet(const u_char *packet_data);
    static void handle_ipv4_packet(const u_char *packet_data);
    static void handle_ipv6_packet(const u_char *packet_data);
    static void handle_icmp_packet(const u_char *packet_data);
    static void handle_http_packet(const u_char *packet_data);
    static void handle_https_packet(const u_char *packet_data);
};

#endif