#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <libnet.h>
#define min(a, b) (((a) < (b)) ? (a) : (b))

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

void print_mac(struct libnet_ethernet_hdr* header) { // print src/dst mac from ethernet header
    printf("src mac: ");
    for (int i = 0; i < 6; i++) {
        printf("%02x", header->ether_shost[i]);
        if (i < 5) printf(":");
    }
    printf("\n");

    printf("dst mac: ");
    for (int i = 0; i < 6; i++) {
        printf("%02x", header->ether_dhost[i]);
        if (i < 5) printf(":");
    }
    printf("\n");
}

void print_ip(struct libnet_ipv4_hdr* header) { // print src/dst ip from IP header
    printf("src ip: ");
    for (int i = 0; i < 4; i++) {
        printf("%d", (header->ip_src.s_addr >> 8 * i) & 0xff);
        if (i < 3) printf(".");
    }
    printf("\n");

    printf("dst ip: ");
    for (int i = 0; i < 4; i++) {
        printf("%d", (header->ip_dst.s_addr >> 8 * i) & 0xff);
        if (i < 3) printf(".");
    }
    printf("\n");
}

void print_port(struct libnet_tcp_hdr* header) { // print src/dst port from TCP header
    printf("src port: %d\ndst port: %d\n", ntohs(header->th_sport), ntohs(header->th_dport));
}

void print_data(char* data_http, int data_len) {
    printf("data: ");
    for (int i = 0; i < min(data_len, 16); i++)
        printf("%02hhx ", data_http[i]);
    if (data_len < 16)
        for (int i = data_len; i < 16; i++)
            printf("00 ");
    printf("\n");
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
        return -1;
    }

    int cnt = 0;
    while (1) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        cnt++;

        struct libnet_ethernet_hdr* header_ethernet = (void*)packet;
        struct libnet_ipv4_hdr* header_ipv4 = (void*)header_ethernet + sizeof(struct libnet_ethernet_hdr);
        if (header_ipv4->ip_p != 0x06) continue; // if not a TCP packet

        struct libnet_tcp_hdr* header_tcp = (void*)header_ipv4 + header_ipv4->ip_hl * 4;
        char* data_http = (void*)header_tcp + header_tcp->th_off * 4;
        int data_len = header->len - (int)((void*)data_http - (void*)packet);

        printf("================= packet number: %d =================\n", cnt);
        print_mac(header_ethernet);
        print_ip(header_ipv4);
        print_port(header_tcp);
        print_data(data_http, data_len);
        printf("======================================================\n\n");
    }

    return 0;
}