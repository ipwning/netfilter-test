#include "nftest.h"
#include "header.h"

const char *HOST;

/* returns packet id */
void dump(unsigned char* buf, int size) {
    int i;
    for (i = 0; i < size; i++) {
        if (i != 0 && i % 16 == 0)
            printf("\n");
        printf("%02X ", buf[i]);
    }
    printf("\n");
}

void ip_debug(ip_header *ip) {
    printf("=========================================\n");
    printf("ver=%d\n", ip->ver);
    printf("header_len=%#x\n", ip->h_len);
    printf("type_of_service=%#x\n", ip->tos);
    printf("total_len=%d\n", ip->total_len);
    printf("id=%#x\n", ip->id);
    printf("reserved flags=%#x\n", ip->frag.reserved_bit);
    printf("no fragment flags=%#x\n", ip->frag.no_fragment_bit);
    printf("more fragment flags=%#x\n", ip->frag.more_fragment_bit);
    printf("fragment_offset=%#x\n", ip->frag.f_off);
    printf("ttl=%#x\n", ip->ttl);
    printf("protocol=%#x\n", ip->protocol);
    printf("checksum=%#x\n", ip->checksum);
    printf("source ip="IP_STR"\n", IP_ARG( ( (uint8_t*)&ip->sip) ) );
    printf("destination ip="IP_STR"\n", IP_ARG( ( (uint8_t*)&ip->dip) ) );
    printf("+++++++++++++++++++++++++++++++++++++++++\n");
}

void tcp_debug(tcp_header *tcp) {
    printf("=========================================\n");
    printf("source port=%d\n", tcp->sport);
    printf("destination port=%d\n", tcp->dport);
    printf("sequence number=%#x\n", tcp->seq_num);
    printf("ack number=%d\n", tcp->ack_num);
    printf("offset=%#x\n", tcp->flags.offset);
    printf("reserved flags=%#x\n", tcp->flags.reserved);
    printf("ns flags=%#x\n", tcp->flags.ns);
    printf("cwr flags=%#x\n", tcp->flags.cwr);
    printf("ece flags=%#x\n", tcp->flags.ece);
    printf("urg flags=%#x\n", tcp->flags.urg);
    printf("ack flags=%#x\n", tcp->flags.ack);
    printf("psh flags=%#x\n", tcp->flags.psh);
    printf("rst flags=%#x\n", tcp->flags.rst);
    printf("syn flags=%#x\n", tcp->flags.syn);
    printf("fin flags=%#x\n", tcp->flags.fin);
    printf("window size=%#x\n", tcp->window);
    printf("checksum=%#x\n", tcp->checksum);
    printf("urgent pointer=%#x\n", tcp->urgent_ptr);
    printf("+++++++++++++++++++++++++++++++++++++++++\n");
}

int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
          struct nfq_data *nfa, void *data) {
    
    struct nfqnl_msg_packet_hdr *ph = NULL;
    tcp_header *tcp = NULL;
    ip_header *ip = NULL;
    int ret;
    int id = 0;
    int http_size;
    int state = NF_ACCEPT;
    unsigned char *_data = NULL;
    unsigned char *http = NULL;
    unsigned char *host = NULL;
    unsigned char *nl = NULL;
    ph = nfq_get_msg_packet_hdr(nfa);
    
    if (ph) id = ntohl(ph->packet_id);
    else return -1;

    ret = nfq_get_payload(nfa, &_data);
    ip = (ip_header*)malloc(sizeof(ip_header) + 1);
    if(!ip) return -1;
    
    memcpy(ip, _data, sizeof(ip_header));
    *(uint16_t*)&ip->frag = ntohs(*(uint16_t*)&ip->frag);
    ip->total_len = ntohs(ip->total_len);
    ip->checksum = ntohs(ip->checksum);
    //ip_debug(ip);

    if(ip->protocol == TCP) {
        tcp = (tcp_header*)malloc(sizeof(tcp_header) + 1);
        if(!tcp) return -1;
        
        memcpy(tcp, _data + (ip->h_len * 4), sizeof(tcp_header));
        *(uint16_t*)&tcp->flags = ntohs(*(uint16_t*)&tcp->flags);
        tcp->sport = ntohs(tcp->sport);
        tcp->dport = ntohs(tcp->dport);
        tcp->seq_num = ntohl(tcp->seq_num);
        tcp->ack_num = ntohl(tcp->ack_num);
        tcp->checksum = ntohs(tcp->checksum);
        tcp->urgent_ptr = ntohs(tcp->urgent_ptr);
        //tcp_debug(tcp);
        
        if(tcp->dport == 80) {
            if(ip->total_len > 44) {
                //ip_debug(ip);
                //tcp_debug(tcp);
                http_size = ip->total_len - (ip->h_len * 4 + tcp->flags.offset * 4);
                if(http_size) { 
                    puts("check the http host.");
                    http = (unsigned char *)malloc(http_size + 1);
                    if(!http) return -1;
                    memcpy(http, _data + (ip->h_len * 4 + tcp->flags.offset * 4), http_size);
                    host = (unsigned char *)strstr((char *)http, "Host: ") + 6;
                    if(host) {
                        nl = (unsigned char *)strstr((char *)host, "\r\n");
                        if(nl) {
                            *nl = '\0';
                            if(!strcmp((const char *)host, HOST)) {
                                printf("%s is filtered!! :(\n", host);
                                //dump(http, http_size);
                                state = NF_DROP;
                            } else printf("%s is safety host. :)\n", host);
                        }
                    }
                }
            }
        }
    }
    free(ip);
    free(tcp);
    free(http);
    return nfq_set_verdict(qh, id, state, 0, NULL);
}

uint32_t print_pkt(struct nfq_data *tb)
{
    int id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    struct nfqnl_msg_packet_hw *hwph;
    uint32_t mark,ifi;
    int ret;
    unsigned char *data;

    ph = nfq_get_msg_packet_hdr(tb);
    if (ph) {
        id = ntohl(ph->packet_id);
        printf("hw_protocol=0x%04x hook=%u id=%u ",
            ntohs(ph->hw_protocol), ph->hook, id);
    }

    hwph = nfq_get_packet_hw(tb);
    if (hwph) {
        int i, hlen = ntohs(hwph->hw_addrlen);

        printf("hw_src_addr=");
        for (i = 0; i < hlen-1; i++)
            printf("%02x:", hwph->hw_addr[i]);
        printf("%02x ", hwph->hw_addr[hlen-1]);
    }

    mark = nfq_get_nfmark(tb);
    if (mark)
        printf("mark=%u ", mark);

    ifi = nfq_get_indev(tb);
    if (ifi)
        printf("indev=%u ", ifi);

    ifi = nfq_get_outdev(tb);
    if (ifi)
        printf("outdev=%u ", ifi);
    ifi = nfq_get_physindev(tb);
    if (ifi)
        printf("physindev=%u ", ifi);

    ifi = nfq_get_physoutdev(tb);
    if (ifi)
        printf("physoutdev=%u ", ifi);

    ret = nfq_get_payload(tb, &data);
    if (ret >= 0) {
        printf("payload_len=%d\n", ret);
        dump(data, ret);
    }
    
    fputc('\n', stdout);

    return id;
}
