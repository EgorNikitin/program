//
// Created by root on 10.10.18.
//

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <errno.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <regex>

#include <netinet/ip.h>
#include <netinet/tcp.h>
extern "C" {
#include <libnetfilter_queue/libnetfilter_queue_tcp.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv4.h>
#include <libnetfilter_queue/pktbuff.h>
}

#include "../extra/checksum.c"

using namespace std;


uint16_t tcp_compute_checksum_ipv4(uint8_t *ipPkt)
{
    struct iphdr *iph;
    struct tcphdr *tcph;

    iph = (struct iphdr *)ipPkt;
    tcph = (struct tcphdr *)(ipPkt + iph->ihl*4);

    /* checksum field in header needs to be zero for calculation. */
    tcph->check = 0;
    return nfq_checksum_tcpudp_ipv4(iph);
}

void print_ip_payload(unsigned char *data, int ret, uint16_t hw_protocol) {

    printf("\n");
    int _count = 0;

    printf("0000\t");
    for(int i = 0; i < 8; i++) {
        printf("%02x ",0);
    }
    printf(" ");
    for (int i = 0; i < 4; ++i) {
        printf("%02x ",0);
    }
    printf("%02x %02x ",(hw_protocol>>8)&0xFF,hw_protocol&0x00FF);

    if (ret < 2)
        return;

    printf("%02x %02x\n",data[0],data[1]);
    _count += 2;
    ret -= 2;

    for(int i = 0; i < ret/16; i++) {

        printf("%03x0\t",i+1);

        for (int j = 0; j < 8; ++j) {
            printf("%02x ",data[_count]);
            _count++;
        }
        printf(" ");
        for (int j = 0; j < 8; ++j) {
            printf("%02x ",data[_count]);
            _count++;
        }
        printf("\n");
    }

    if ( 0 < ret % 16 )
        printf("%03x0\t", ret/16 + 1);

    for (int j = 0; j < ret % 16 && j < 8; ++j) {
        printf("%02x ",data[_count]);
        _count++;
    }
    printf(" ");
    for (int j = 0; j < (ret % 16 - 8) && j < 8; ++j) {
        printf("%02x ",data[_count]);
        _count++;
    }
    printf("\n\n");
}

class data_dto {
public:
    data_dto(uint32_t id, unsigned char *data, uint32_t data_len) : id(id), data(data), data_len(data_len) {}

    uint32_t id;
    unsigned char* data;
    uint32_t data_len;
};

bool findString(const char *data,uint32_t data_len, const string regexp) {

    string sdata (data,data_len);
    regex e (regexp);

    return regex_search (sdata,e);
}

pair<uint8_t*,uint32_t > *get_tcp_payload(uint8_t *ip_pkt, uint32_t ip_len) {

    pkt_buff *pktBuff;
    iphdr *iph;
    tcphdr *tcph;
    uint8_t *tcp_payload;
    uint32_t tcp_payload_len;

    if ( ( pktBuff = pktb_alloc (AF_INET, ip_pkt, ip_len, 0)) == nullptr) {
        return nullptr;
    }
    if ( ( iph = nfq_ip_get_hdr (pktBuff)) == nullptr) {
        return nullptr;
    }
    if ( nfq_ip_set_transport_header (pktBuff,iph) == -1) {
        return nullptr;
    }
    if ( ( tcph = nfq_tcp_get_hdr (pktBuff) ) == nullptr) {
        return nullptr;
    }
    if ( (tcp_payload = (uint8_t*) nfq_tcp_get_payload (tcph,pktBuff))  == nullptr) {
        return nullptr;
    }
    tcp_payload_len = nfq_tcp_get_payload_len(tcph,pktBuff);

    return new pair<uint8_t*,uint32_t > (tcp_payload,tcp_payload_len);
}