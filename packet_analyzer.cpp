#include "packet_analyzer.h"

Analyzer::Analyzer(std::string fileName)
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    handle = pcap_open_offline(fileName.c_str(), errbuf);

    pcap_loop(handle, 0, packet_handler, NULL);
}

void Analyzer::packet_handler(unsigned char *user_data, const struct pcap_pkthdr *packet_header, const unsigned char *packet_data)
{
    initscr();
    clear();
    refresh();

    struct ether_header *ethernet_header = (struct ether_header *)packet_data;

    const unsigned char *src_mac = ethernet_header->ether_shost;
    std::string src_mac_str = ether_ntoa(reinterpret_cast<const ether_addr *>(src_mac));

    const unsigned char *dest_mac = ethernet_header->ether_dhost;
    std::string dest_mac_str = ether_ntoa(reinterpret_cast<const ether_addr *>(dest_mac));

    printw("Ethernet Header:\n");
    printw("\tSource MAC Address: %s\n", src_mac_str.c_str());
    printw("\tDestination MAC Address: %s\n", dest_mac_str.c_str());

    uint16_t ether_type = ntohs(ethernet_header->ether_type);

    if (ether_type == ETHERTYPE_IP)
    {
        handle_ipv4_packet(packet_data + sizeof(struct ether_header));
    }
    else if (ether_type == ETHERTYPE_IPV6)
    {
        handle_ipv6_packet(packet_data + sizeof(struct ether_header));
    }
    else if (ether_type == ETHERTYPE_ARP)
    {
        handle_arp_packet(packet_data + sizeof(struct ether_header));
    }

    printw("Press Enter to clear the screen...");
    refresh();

    nodelay(stdscr, TRUE);

    bool enterPressed = false;
    int ch;
    while (!enterPressed)
    {
        ch = getch();
        if (ch == '\n')
        {
            enterPressed = true;
        }
    }
}

void Analyzer::handle_ipv4_packet(const u_char *packet_data)
{
    struct ip *ip_header = (struct ip *)(packet_data);
    uint8_t protocol = ip_header->ip_p;

    const char *destination_ip = inet_ntoa(ip_header->ip_dst);
    const char *source_ip = inet_ntoa(ip_header->ip_src);
    uint8_t ttl = ip_header->ip_ttl;

    printw("\tSource IP: %s\n", source_ip);
    printw("\tDestination IP: %s\n", destination_ip);
    printw("\tTTL: %u\n", ttl);

    if (protocol == IPPROTO_TCP)
    {
        handle_tcp_packet(packet_data + sizeof(struct ip));
    }
    else if (protocol == IPPROTO_UDP)
    {
        handle_udp_packet(packet_data + sizeof(struct ip));
    }
    else if (protocol == IPPROTO_ICMP)
    {
        handle_icmp_packet(packet_data + sizeof(struct ip));
    }
}

void Analyzer::handle_ipv6_packet(const u_char *packet_data)
{
    struct ip6_hdr *ipv6_header = (struct ip6_hdr *)(packet_data);
    uint8_t protocol = ipv6_header->ip6_nxt;

    struct in6_addr source_ip = ipv6_header->ip6_src;
    char source_ip_str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &source_ip, source_ip_str, INET6_ADDRSTRLEN);

    struct in6_addr destination_ip = ipv6_header->ip6_dst;
    char destination_ip_str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &destination_ip, destination_ip_str, INET6_ADDRSTRLEN);

    printw("IP Protocol (IPv6): %d\n", static_cast<int>(protocol));
    printw("\tSource IP (IPv6): %s\n", source_ip_str);
    printw("\tDestination IP (IPv6): %s\n", destination_ip_str);
}

void Analyzer::handle_arp_packet(const u_char *packet_data)
{
    struct ether_arp *arp_header = (struct ether_arp *)(packet_data);

    printw("ARP Header Information:\n");
    printw("\tHardware Type: %u\n", ntohs(arp_header->arp_hrd));
    printw("\tProtocol Type: 0x%04x\n", ntohs(arp_header->arp_pro));
    printw("\tHardware Address Length: %u\n", arp_header->arp_hln);
    printw("\tProtocol Address Length: %u\n", arp_header->arp_pln);
    printw("\tOperation: %u\n", ntohs(arp_header->arp_op));
    printw("\tSender MAC Address: %02X:%02X:%02X:%02X:%02X:%02X\n",
           arp_header->arp_sha[0], arp_header->arp_sha[1], arp_header->arp_sha[2],
           arp_header->arp_sha[3], arp_header->arp_sha[4], arp_header->arp_sha[5]);
    printw("\tSender IP Address: %u.%u.%u.%u\n",
           arp_header->arp_spa[0], arp_header->arp_spa[1], arp_header->arp_spa[2], arp_header->arp_spa[3]);
    printw("\tTarget MAC Address: %02X:%02X:%02X:%02X:%02X:%02X\n",
           arp_header->arp_tha[0], arp_header->arp_tha[1], arp_header->arp_tha[2],
           arp_header->arp_tha[3], arp_header->arp_tha[4], arp_header->arp_tha[5]);
    printw("\tTarget IP Address: %u.%u.%u.%u\n",
           arp_header->arp_tpa[0], arp_header->arp_tpa[1], arp_header->arp_tpa[2], arp_header->arp_tpa[3]);
}

void Analyzer::handle_tcp_packet(const u_char *packet_data)
{
    struct tcphdr *tcp_header = (struct tcphdr *)(packet_data);

    printw("TCP Header Information:\n");
    printw("\tSource Port: %u\n", ntohs(tcp_header->source));
    printw("\tDestination Port: %u\n", ntohs(tcp_header->dest));
    printw("\tSequence Number: %u\n", ntohl(tcp_header->seq));
    printw("\tAcknowledgment Number: %u\n", ntohl(tcp_header->ack_seq));
    printw("\tData Offset: %u\n", tcp_header->doff);
    printw("\tFlags:\n");
    printw("\t  SYN: %d\n", tcp_header->syn);
    printw("\t  ACK: %d\n", tcp_header->ack);
    printw("\t  FIN: %d\n", tcp_header->fin);
    printw("\t  RST: %d\n", tcp_header->rst);
    printw("\tWindow Size: %u\n", ntohs(tcp_header->window));
    printw("\tChecksum: 0x%04x\n", ntohs(tcp_header->check));
    printw("\tUrgent Pointer: %u\n", ntohs(tcp_header->urg_ptr));

    if (ntohs(tcp_header->th_dport) == 80)
    {
        handle_http_packet(packet_data);
    }
    else if (ntohs(tcp_header->th_dport) == 443)
    {
        handle_https_packet(packet_data);
    }
}

void Analyzer::handle_udp_packet(const u_char *packet_data)
{
    struct udphdr *udp_header = (struct udphdr *)(packet_data);

    printw("UDP Header Information:\n");
    printw("\tSource Port: %u\n", ntohs(udp_header->source));
    printw("\tDestination Port: %u\n", ntohs(udp_header->dest));
    printw("\tLength: %u\n", ntohs(udp_header->len));
    printw("\tChecksum: 0x%04X\n", ntohs(udp_header->check));

    if (ntohs(udp_header->dest) == 53 || ntohs(udp_header->source) == 53)
    {
        handle_dns_packet(packet_data + sizeof(struct udphdr));
    }
}

void Analyzer::handle_icmp_packet(const u_char *packet_data)
{

    struct icmphdr *icmp_header = (struct icmphdr *)(packet_data);

    printw("ICMPv4 Packet Information:\n");
    printw("\tType: %u\n", icmp_header->type);
    printw("\tCode: %u\n", icmp_header->code);
    printw("\tChecksum: 0x%04x\n", ntohs(icmp_header->checksum));
    printw("\tIdentifier: 0x%04x\n", ntohs(icmp_header->un.echo.id));
    printw("\tSequence Number: %u\n", ntohs(icmp_header->un.echo.sequence));
}

void Analyzer::handle_http_packet(const u_char *packet_data)
{
    printw("HTTP Packet\n");
}

void Analyzer::handle_https_packet(const u_char *packet_data)
{
    printw("HTTP Packet\n");
}

void Analyzer::handle_dns_packet(const u_char *packet_data)
{
    printw("DNS\n");
}