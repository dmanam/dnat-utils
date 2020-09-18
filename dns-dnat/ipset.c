/* ipset-dns: lightweight DNS IPSet forwarding server
 * by Jason A. Donenfeld (zx2c4) <Jason@zx2c4.com>
 *
 * This is a lightweight DNS forwarding server that adds all resolved IPs
 * to a given netfilter ipset. It is designed to be used in conjunction with
 * dnsmasq's upstream server directive.
 *
 * Copyright (C) 2013, 2017 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 * DNS parsing code loosely based on uClibc's resolv.c:
 * Copyright (C) 1998 Kenneth Albanowski <kjahds@kjahds.com>, The Silver Hammer Group, Ltd.
 * Copyright (C) 1985, 1993 The Regents of the University of California. All Rights Reserved.
 * This file is licensed under the GPLv2. Please see COPYING for more information.
 *
 *
 * Usage Example:
 *
 * In dnsmasq.conf:
 *     server=/c.youtube.com/127.0.0.1#1919
 * Make an ipset:
 *     # ipset -N youtube iphash
 * Start the ipset-dns server:
 *     # ipset-dns youtube "" 1919 8.8.8.8
 * Query a hostname:
 *     # host r4---bru02t12.c.youtube.com
 *     r4---bru02t12.c.youtube.com is an alias for r4.bru02t12.c.youtube.com.
 *     r4.bru02t12.c.youtube.com has address 74.125.216.51
 * Observe that it was added to the ipset:
 *     # ipset -L youtube
 *     Name: youtube
 *     Type: iphash
 *     References: 1
 *     Header: hashsize: 1024 probes: 8 resize: 50
 *     Members:
 *     74.125.216.51
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/nameser.h>
#include <arpa/inet.h>
#include <libmnl/libmnl.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/ipset/ip_set.h>

int ipset_add(const char *setname, in_addr_t ipaddr)
{
    struct nlmsghdr *nlh;
    struct nfgenmsg *nfg;
    struct mnl_socket *mnl;
    struct nlattr *nested[2];
    char buffer[256];
    int rc;
    struct in_addr addr = (struct in_addr){ipaddr};

    rc = 0;

    if (strlen(setname) >= IPSET_MAXNAMELEN) {
        errno = ENAMETOOLONG;
        return -1;
    }

    nlh = mnl_nlmsg_put_header(buffer);
    nlh->nlmsg_type = IPSET_CMD_ADD | (NFNL_SUBSYS_IPSET << 8);
    nlh->nlmsg_flags = NLM_F_REQUEST;

    nfg = mnl_nlmsg_put_extra_header(nlh, sizeof(struct nfgenmsg));
    nfg->nfgen_family = AF_INET;
    nfg->version = NFNETLINK_V0;
    nfg->res_id = htons(0);

    mnl_attr_put_u8(nlh, IPSET_ATTR_PROTOCOL, IPSET_PROTOCOL);
    mnl_attr_put(nlh, IPSET_ATTR_SETNAME, strlen(setname) + 1, setname);
    nested[0] = mnl_attr_nest_start(nlh, IPSET_ATTR_DATA);
    nested[1] = mnl_attr_nest_start(nlh, IPSET_ATTR_IP);
    mnl_attr_put(nlh, IPSET_ATTR_IPADDR_IPV4
            | NLA_F_NET_BYTEORDER, sizeof(struct in_addr), &addr);
    mnl_attr_nest_end(nlh, nested[1]);
    mnl_attr_nest_end(nlh, nested[0]);

    mnl = mnl_socket_open(NETLINK_NETFILTER);
    if (!mnl)
        return -1;
    if (mnl_socket_bind(mnl, 0, MNL_SOCKET_AUTOPID) < 0) {
        rc = -1;
        goto close;
    }
    if (mnl_socket_sendto(mnl, nlh, nlh->nlmsg_len) < 0) {
        rc = -1;
        goto close;
    }
close:
    mnl_socket_close(mnl);
    return rc;
}
