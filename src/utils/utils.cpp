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

using namespace std;

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

int test_regex_search() {

    unsigned char data[] = { 0x45, 0x00, 0x00, 0x4b, 0x2f, 0xa5, 0x40, 0x00, 0x40, 0x06, 0xe8, 0xc5, 0x6f, 0xde, 0x21, 0x85,
                             0x6f, 0xde, 0x21, 0x01, 0xd0, 0xfe, 0x0b, 0xb8, 0xde, 0xa4, 0xde, 0x0f, 0xc2, 0x76, 0x63, 0xdb,
                             0x50, 0x18, 0x72, 0x10, 0x5a, 0xe5, 0x00, 0x00, 0x47, 0x45, 0x54, 0x20, 0x2f, 0x20, 0x48, 0x54,
                             0x54, 0x50, 0x2f, 0x31, 0x2e, 0x30, 0x0a, 0x48, 0x6f, 0x73, 0x74, 0x3a, 0x20, 0x31, 0x31, 0x31,
                             0x2e, 0x32, 0x32, 0x32, 0x2e, 0x33, 0x33, 0x2e, 0x31, 0x0a, 0x0a };
    unsigned int data_len = sizeof(data)/ sizeof(*data);

    pair<uint8_t *, uint32_t > *p = get_tcp_payload(data, data_len);

    if (p == nullptr) {
        cout << "Oops!" << endl;
        return 0;
    }

    string sdata ( (char*) p->first, p->second);
    regex e ("111\\.2");

    if (regex_search (sdata,e)) {
        cout << "Yes" << endl;
    } else {
        cout << "No" << endl;
    }

    return 0;
}