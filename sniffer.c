#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#include <netinet/in.h>
#include <time.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#define APP_NAME "sniffer"
#define MAX_FILENAME 256
#define MAC_ADDRSTRLEN 2 * 6 + 5 + 1

char *mac_ntoa(u_char *d)
{
    static char str[MAC_ADDRSTRLEN];

    snprintf(str, sizeof(str), "%02x:%02x:%02x:%02x:%02x:%02x", d[0], d[1], d[2], d[3], d[4], d[5]);

    return str;
}

char *ip_ntoa(void *i)
{
    static char str[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, i, str, sizeof(str));

    return str;
}
void dump_udp(u_int32_t length, const u_char *content)
{
    struct ip *ip = (struct ip *)(content + ETHER_HDR_LEN);
    struct udphdr *udp = (struct udphdr *)(content + ETHER_HDR_LEN + (ip->ip_hl << 2));

    u_int16_t source_port = ntohs(udp->uh_sport);
    u_int16_t destination_port = ntohs(udp->uh_dport);

    printf("Source Port: %u\n", source_port);
    printf("Destination Port:  %u\n", destination_port);
}
void dump_tcp(u_int32_t length, const u_char *content)
{
    struct ip *ip = (struct ip *)(content + ETHER_HDR_LEN);
    struct udphdr *tcp = (struct udphdr *)(content + ETHER_HDR_LEN + (ip->ip_hl << 2));

    u_int16_t source_port = ntohs(tcp->uh_sport);
    u_int16_t destination_port = ntohs(tcp->uh_dport);

    printf("Source Port: %u\n", source_port);
    printf("Destination Port:  %u\n",destination_port);
}

void dump_ip(u_int32_t length, const u_char *content)
{
    struct ip *ip = (struct ip *)(content + ETHER_HDR_LEN);

    u_char protocol = ip->ip_p;
    char src_ip[INET_ADDRSTRLEN] = {0};
    char dst_ip[INET_ADDRSTRLEN] = {0};

    //copy ip address
    snprintf(src_ip, sizeof(src_ip), "%s", ip_ntoa(&ip->ip_src));
    snprintf(dst_ip, sizeof(dst_ip), "%s", ip_ntoa(&ip->ip_dst));

    printf("Source IP Address: %s\n", src_ip);
    printf("Destination IP Address: %s\n", dst_ip);

    switch (protocol)
    {
    case IPPROTO_UDP:
        //printf("Next is UDP\n");
        dump_udp(length, content);
        break;

    case IPPROTO_TCP:
        //printf("Next is TCP\n");
        dump_tcp(length, content);
        break;

    default:
        //printf("Next is %d\n", protocol);
        break;
    }
}

void dump_ethernet(u_int32_t length, const u_char *content)
{
    char dst_mac[MAC_ADDRSTRLEN] = {0};
    char src_mac[MAC_ADDRSTRLEN] = {0};
    u_int16_t type;

    struct ether_header *ethernet = (struct ether_header *)content;

    snprintf(dst_mac, sizeof(dst_mac), "%s", mac_ntoa(ethernet->ether_dhost));
    snprintf(src_mac, sizeof(src_mac), "%s", mac_ntoa(ethernet->ether_shost));
    type = ntohs(ethernet->ether_type);

    if (type < 1500)
        printf("Length:%5u\n", type);
    else
        printf("Ethernet Type:0x%04x\n", type);

    printf("\nDestination MAC Address: %s\n", dst_mac);
    printf("Source MAC Address     : %s\n", src_mac);

    switch (type)
    {
    case ETHERTYPE_IP:
        //printf("IP\n");
        dump_ip(length, content);
        break;

    default:
        //printf("%#06x\n", type);
        break;
    }
}

void print_error_input(void)
{

    printf("Usage: %s [local_pacp_filename]\n", APP_NAME);
    printf("\n");
    exit(1);
}

int main(int argc, char *argv[])
{
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    char filename[MAX_FILENAME] = "";
    pcap_t *handle; /* packet capture handle */

    if (argc < 2)
    {
        print_error_input();
        exit(1);
    }

    dev = pcap_lookupdev(errbuf);

    if (dev == NULL)
    {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return (2);
    }
    printf("Device: %s\n", dev);

    strcpy(filename, argv[1]);
    handle = pcap_open_offline(filename, errbuf);
    if (!handle)
    {
        fprintf(stderr, "pcap_open_offline(): %s\n", errbuf);
        exit(1);
    }
    printf("Open: %s\n", filename);

    struct pcap_pkthdr *header = NULL;
    const u_char *content = NULL;
    int ret;
    int count = 0;
    while (ret = pcap_next_ex(handle, &header, &content) >= 0)
    {
        printf("\nPacket number %d:\n", count);
        count++;

        printf("Time: %s", ctime((const time_t *)&header->ts.tv_sec));
        printf("Length: %d bytes\n", header->len);

        dump_ethernet(header->caplen, content);

        struct tcphdr *tcp;

        tcp = (struct tcphdr *)(content + sizeof(struct ether_header) + sizeof(struct ip));

        //printf("Source Port:       %5u| Destination Port:  %5u|\n", source_port, destination_port);
    }

    pcap_close(handle);

    printf("\nCapture complete.\n");

    return 0;

    return (0);
}