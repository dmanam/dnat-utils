#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack_tcp.h>

#include "nat_table.h"

static struct nfct_handle *handle;

int nfct_init(void) {
    handle = nfct_open(CONNTRACK, 0);
    if (!handle) {
        return -1;
    }
    return 0;
}

void nfct_cleanup(void) {
  nfct_close(handle);
}

union l4hdr {
    struct tcphdr tcp;
    struct udphdr udp;
    struct icmphdr icmp;
};

in_addr_t nfct_add(uint8_t *pkt) {
    int ret;
    struct nf_conntrack *ct;

    struct iphdr *ip = (struct iphdr *) pkt;
    union l4hdr *l4 = (union l4hdr *) (pkt + 4 * ip->ihl);

    in_addr_t new_daddr = nt_lookup(ip->daddr);
    if (new_daddr == (in_addr_t) -1) {
      return 0;
    }

    ct = nfct_new();
    if (!ct) {
        perror("nfct_new");
        return -1;
    }

    nfct_set_attr_u8(ct, ATTR_L3PROTO, AF_INET);
    nfct_set_attr_u32(ct, ATTR_IPV4_SRC, ip->saddr);
    nfct_set_attr_u32(ct, ATTR_IPV4_DST, ip->daddr);
    nfct_set_attr_u8(ct, ATTR_L4PROTO, ip->protocol);
    switch (ip->protocol) {
        case IPPROTO_TCP:
            nfct_set_attr_u16(ct, ATTR_PORT_SRC, l4->tcp.source);
            nfct_set_attr_u16(ct, ATTR_PORT_DST, l4->tcp.dest);
            nfct_set_attr_u8(ct, ATTR_TCP_STATE, TCP_CONNTRACK_ESTABLISHED);
            break;
        case IPPROTO_UDP:
            nfct_set_attr_u16(ct, ATTR_PORT_SRC, l4->udp.source);
            nfct_set_attr_u16(ct, ATTR_PORT_DST, l4->udp.dest);
            break;
        case IPPROTO_ICMP:
            nfct_set_attr_u8(ct, ATTR_ICMP_TYPE, l4->icmp.type);
            nfct_set_attr_u8(ct, ATTR_ICMP_CODE, l4->icmp.code);
            if (l4->icmp.type == ICMP_ECHO || l4->icmp.type == ICMP_ECHOREPLY) {
                nfct_set_attr_u16(ct, ATTR_ICMP_ID, l4->icmp.un.echo.id);
            }
            break;
    };

    nfct_setobjopt(ct, NFCT_SOPT_SETUP_REPLY);

    nfct_set_attr_u32(ct, ATTR_TIMEOUT, 120);

    nfct_set_attr_u32(ct, ATTR_DNAT_IPV4, new_daddr);

    ret = nfct_query(handle, NFCT_Q_GET, ct);
    if (ret == -1) {
        char s_saddr[16], s_daddr[16], s_naddr[16], s_proto[9], s_sport[7], s_dport[7];
        inet_ntop(AF_INET, &(ip->saddr), s_saddr, 16);
        inet_ntop(AF_INET, &(ip->daddr), s_daddr, 16);
        inet_ntop(AF_INET,   &new_daddr, s_naddr, 16);
        switch (ip->protocol) {
            case IPPROTO_TCP:
                sprintf(s_proto, "TCP");
                snprintf(s_sport, 7, ":%u", ntohs(l4->tcp.source));
                snprintf(s_dport, 7, ":%u", ntohs(l4->tcp.dest));
                break;
            case IPPROTO_UDP:
                sprintf(s_proto, "UDP");
                snprintf(s_sport, 7, ":%u", ntohs(l4->udp.source));
                snprintf(s_dport, 7, ":%u", ntohs(l4->udp.dest));
                break;
            case IPPROTO_ICMP:
                snprintf(s_proto, 9, "ICMP %u", l4->icmp.type);
                s_sport[0] = s_dport[0] = '\0';
                break;
        }
        fprintf(stderr, "%s connection from %s%s to %s%s via %s\n", s_proto, s_saddr, s_sport, s_naddr, s_dport, s_daddr);

        ret = nfct_query(handle, NFCT_Q_CREATE, ct);
        if (ret == -1) {
            perror("nfct_query");
        }
    }

    nfct_destroy(ct);

    if (ret == -1) return (in_addr_t) ret;

    return new_daddr;
}
