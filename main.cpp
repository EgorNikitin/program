#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>

#include <iostream>
#include <fstream>
#include <vector>
#include <string>

#include <libnetfilter_queue/libnetfilter_queue.h>
extern "C" {
#include <libnetfilter_queue/libnetfilter_queue_tcp.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv4.h>
#include <libnetfilter_queue/pktbuff.h>
}

#include "internal.h"
#include "./src/utils/utils.cpp"
#include "./src/rules/rules.cpp"

#include <algorithm>

using namespace std;

std::string payloadStringN;
uint32_t numberPayloadString = 6;

static data_dto handle_pkt(struct nfq_data *tb) {

    int id = 0;
    uint32_t ret;
    unsigned char *data;
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(tb);
    uint16_t hw_protocol = 0;

    if (ph) {
        id = ntohl(ph->packet_id);
        hw_protocol = ntohs(ph->hw_protocol);
        printf("hook=%u\t//\tid=%u ", ph->hook, id);
    }

    ret = nfq_get_payload(tb, &data);
    if (ret >= 0) {
        printf("\t//\tlen = %d\t//\tip_payload_len = %d\n", ret+14, ret);
        /*if (id == 1) {
            printf("MSS = %02x %02x\n",data[0x38-14],data[0x39-14]);
            data[0x38-14] = 0x1;
            data[0x39-14] = 0x0;
        }*/
        pair<uint8_t *, uint32_t > *p = get_tcp_payload(data,ret);
        if (p != nullptr) {
            string sdata ( (char*) p->first,p->second);
            regex myRegexp(payloadStringN);
            if(regex_search(sdata,myRegexp)) {
                cout << endl << "FIND! id= " << id << " str= " << payloadStringN << endl;
            }
        }

        print_ip_payload(data, ret, hw_protocol);
    }

    return data_dto(id,data,ret);
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data) {

    data_dto t = handle_pkt(nfa);
//    printf("entering callback\n");
//    return nfq_set_verdict(qh, t.id, NF_ACCEPT, t.data_len, t.data);
    return nfq_set_verdict(qh, t.id, NF_ACCEPT, 0, NULL);
}

std::string getPayloadStringN(uint32_t N) {

    vector<Rule> rules;
    vector<string> v = readFileRules();
    for (auto &x: v) {
        vector<string> temp = split(x,',');
        Rule rule(
                split(temp[0],':')[1],
                split(temp[1],':')[1],
                split(temp[2],':')[1],
                split(temp[3],':')[1],
                split(temp[4],':')[1]
        );
        rules.push_back(rule);
    }

    if (N >= v.size() || N < 0)
        N = 0;

    return rules[N-1].payload;
}

int main(int argc, char **argv) {

    uint32_t queue = 0;
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    payloadStringN = preparePayloadString(getPayloadStringN(numberPayloadString));
    printf("payloadStringN = |");
    for (auto x : payloadStringN) {
            printf("%02x|",x);
    }
    std::cout << std::endl;

    if (argc == 2) {
        queue = atoi(argv[1]);
        if (queue > 65535) {
            fprintf(stderr, "Usage: %s [<0-65535>]\n", argv[0]);
            exit(EXIT_FAILURE);
        } else {
            printf("--queue-num= %s\n\n", argv[1]);
        }
    }

    printf("opening library handle\n");
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    printf("binding this socket to queue '%d'\n", queue);
    qh = nfq_create_queue(h, queue, &cb, NULL);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    printf("setting flags to request UID and GID\n");
    if (nfq_set_queue_flags(qh, NFQA_CFG_F_UID_GID, NFQA_CFG_F_UID_GID)) {
        fprintf(stderr, "This kernel version does not allow to "
                        "retrieve process UID/GID.\n");
    }

    printf("setting flags to request security context\n");
    if (nfq_set_queue_flags(qh, NFQA_CFG_F_SECCTX, NFQA_CFG_F_SECCTX)) {
        fprintf(stderr, "This kernel version does not allow to "
                        "retrieve security context.\n");
    }

    printf("\nWaiting for packets...\n\n");

    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));
    fd = nfq_fd(h);

    for (;;) {
        if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {

            //printf("pkt received\n");

            nfq_handle_packet(h, buf, rv);

            continue;
        }
        if (rv < 0 && errno == ENOBUFS) {
            printf("losing packets!\n");
            continue;
        }
        perror("recv failed");
        break;
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);

#ifdef INSANE
 normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too !

	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

    printf("closing library handle\n");
    nfq_close(h);

    exit(0);
}