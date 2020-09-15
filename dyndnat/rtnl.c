// taken largely from libmnl examples

#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <strings.h>
#include <net/if.h>
#include <pthread.h>

#include <libmnl/libmnl.h>
#include <linux/if_link.h>
#include <linux/rtnetlink.h>

#include "nat_table.h"

#define RTPROT 67

static bool initialized = false;
static int iface;
static unsigned char table;
pthread_mutex_t _rtnl_mutex = PTHREAD_MUTEX_INITIALIZER;

int rtnl_init(unsigned char rt_table, char *iface_name) {
    iface = if_nametoindex(iface_name);
    if (iface == 0) {
        perror("if_nametoindex");
        exit(EXIT_FAILURE);
    }

    table = rt_table;

    initialized = true;

    return 0;
}

static void rtnl_del_route(struct mnl_socket *nl, uint32_t portid, char *buf, in_addr_t dst) {
    struct nlmsghdr *nlh;
    struct rtmsg *rtm;
    uint32_t seq;
    int ret;

    nlh = mnl_nlmsg_put_header(buf);
    nlh->nlmsg_type = RTM_DELROUTE;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_ACK;
    nlh->nlmsg_seq = seq = time(NULL);

    rtm = mnl_nlmsg_put_extra_header(nlh, sizeof(struct rtmsg));
    rtm->rtm_family = AF_INET;
    rtm->rtm_dst_len = 32;
    rtm->rtm_src_len = 0;
    rtm->rtm_tos = 0;
    rtm->rtm_protocol = RTPROT;
    rtm->rtm_table = table;
    rtm->rtm_type = RTN_UNICAST;
    rtm->rtm_scope = RT_SCOPE_LINK;
    rtm->rtm_flags = 0;

    mnl_attr_put_u32(nlh, RTA_DST, dst);

    mnl_attr_put_u32(nlh, RTA_OIF, iface);

    if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
        perror("rtnl_del_route: mnl_socket_sendto");
        exit(EXIT_FAILURE);
    }

    ret = mnl_socket_recvfrom(nl, buf, MNL_SOCKET_BUFFER_SIZE);
    if (ret < 0) {
        perror("rtnl_del_route: mnl_socket_recvfrom");
        exit(EXIT_FAILURE);
    }
}

static void rtnl_add_route(struct mnl_socket *nl, uint32_t portid, char *buf, in_addr_t dst)
{
    struct nlmsghdr *nlh;
    struct rtmsg *rtm;
    uint32_t seq;
    int ret;

    nlh = mnl_nlmsg_put_header(buf);
    nlh->nlmsg_type = RTM_NEWROUTE;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_ACK;
    nlh->nlmsg_seq = seq = time(NULL);

    rtm = mnl_nlmsg_put_extra_header(nlh, sizeof(struct rtmsg));
    rtm->rtm_family = AF_INET;
    rtm->rtm_dst_len = 32;
    rtm->rtm_src_len = 0;
    rtm->rtm_tos = 0;
    rtm->rtm_protocol = RTPROT;
    rtm->rtm_table = table;
    rtm->rtm_type = RTN_UNICAST;
    rtm->rtm_scope = RT_SCOPE_LINK;
    rtm->rtm_flags = 0;

    mnl_attr_put_u32(nlh, RTA_DST, dst);

    mnl_attr_put_u32(nlh, RTA_OIF, iface);

    if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
        perror("rtnl_add_route: mnl_socket_sendto");
        exit(EXIT_FAILURE);
    }

    ret = mnl_socket_recvfrom(nl, buf, MNL_SOCKET_BUFFER_SIZE);
    if (ret < 0) {
        perror("rtnl_add_route: mnl_socket_recvfrom");
        exit(EXIT_FAILURE);
    }
}

struct rtnl_info {
    struct mnl_socket *nl;
    uint32_t portid;
    char *buf;
};

static int rtnl_clear_cb_cb(const struct nlattr *attr, void *data) {
    struct in_addr *addr;
    struct rtnl_info *info = (struct rtnl_info *) data;
    int type = mnl_attr_get_type(attr);

    if (type == RTA_DST) {
        addr = mnl_attr_get_payload(attr);
        rtnl_del_route(info->nl, info->portid, info->buf, addr->s_addr);
    }
    return MNL_CB_OK;
}

static int rtnl_clear_cb(const struct nlmsghdr *nlh, void *data) {
    struct rtmsg *rm = mnl_nlmsg_get_payload(nlh);
    mnl_attr_parse(nlh, sizeof(*rm), rtnl_clear_cb_cb, data);
    return MNL_CB_OK;
}

static void rtnl_clear(struct mnl_socket *nl, uint32_t portid, char *buf) {
    unsigned int seq;
    struct nlmsghdr *nlh;
    struct rtmsg *rtm;
    struct rtnl_info info;
    int ret;

    nlh = mnl_nlmsg_put_header(buf);
    nlh->nlmsg_type = RTM_GETROUTE;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    nlh->nlmsg_seq = seq = time(NULL);
    rtm = mnl_nlmsg_put_extra_header(nlh, sizeof(struct rtmsg));
    rtm->rtm_family = AF_INET;

    if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
        perror("rtnl_clear: mnl_socket_sendto");
        exit(EXIT_FAILURE);
    }

    info.nl = mnl_socket_open(NETLINK_ROUTE);
    if (info.nl == NULL) {
        perror("rtnl_update: mnl_socket_open");
        exit(EXIT_FAILURE);
    }

    if (mnl_socket_bind(info.nl, 0, MNL_SOCKET_AUTOPID) < 0) {
        perror("rtnl_update: mnl_socket_bind");
        exit(EXIT_FAILURE);
    }
    info.portid = mnl_socket_get_portid(info.nl);

    char info_buf[MNL_SOCKET_BUFFER_SIZE];
    info.buf = info_buf;

    ret = mnl_socket_recvfrom(nl, buf, MNL_SOCKET_BUFFER_SIZE);
    while (ret > 0) {
        ret = mnl_cb_run(buf, ret, seq, portid, rtnl_clear_cb, &info);
        if (ret <= MNL_CB_STOP)
            break;
        ret = mnl_socket_recvfrom(nl, buf, MNL_SOCKET_BUFFER_SIZE);
    }
    if (ret == -1) {
        perror("rtnl_clear: mnl_socket_recvfrom");
        exit(EXIT_FAILURE);
    }

    mnl_socket_close(info.nl);
}

void rtnl_update(void) {
    if (!initialized) {
        return;
    }

    struct mnl_socket *nl;
    uint32_t portid;
    char buf[MNL_SOCKET_BUFFER_SIZE];
    const in_addr_t *addrs;
    uint16_t naddrs;

    fprintf(stderr, "updating routes\n");

    pthread_mutex_lock(&_rtnl_mutex);

    nl = mnl_socket_open(NETLINK_ROUTE);
    if (nl == NULL) {
        perror("rtnl_update: mnl_socket_open");
        exit(EXIT_FAILURE);
    }

    if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
        perror("rtnl_update: mnl_socket_bind");
        exit(EXIT_FAILURE);
    }
    portid = mnl_socket_get_portid(nl);

    rtnl_clear(nl, portid, buf);

    nt_vals_iter(&addrs, &naddrs);
    for (uint16_t i = 0; i < naddrs; ++i) {
        rtnl_add_route(nl, portid, buf, addrs[i]);
    }
    nt_vals_iter_end();

    mnl_socket_close(nl);

    pthread_mutex_unlock(&_rtnl_mutex);
}
