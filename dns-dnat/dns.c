/*
 * Based on code from "Fast portable non-blocking network programming with Libevent", with the following license (3-clause BSD):
 *
 * Copyright 2009-2012 Nick Mathewson
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
 *
 *     Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
 *
 *     Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
 *
 *     Neither the names of the copyright owners nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>

#include <sys/socket.h>

#include <event2/dns.h>
#include <event2/dns_struct.h>
#include <event2/util.h>
#include <event2/event.h>

#include <udns.h>

#include "ipset.h"
#include "nat_table.h"

struct cb_data {
    struct dns_ctx *ctx;
    char *ipset;
};

static void server_cb(struct evdns_server_request *req, void *data_void) {
    int err = DNS_ERR_NONE;
    struct cb_data *data = (struct cb_data *) data_void;
    struct dns_rr_a4 *ans;

    for (uint16_t i = 0; i < req->nquestions; ++i) {
        const struct evdns_server_question *q = req->questions[i];
        int ret;

        if (q->type != EVDNS_TYPE_A) {
            err = DNS_ERR_NOTEXIST;
            continue;
        }

        ans = dns_resolve_a4(data->ctx, q->name, 0);
        if (!ans) {
            switch (dns_status(data->ctx)) {
                case DNS_E_NXDOMAIN:
                    err = DNS_ERR_NOTEXIST;
                    continue;
                case DNS_E_NODATA:
                    err = DNS_ERR_NODATA;
                    continue;
                default:
                    err = DNS_ERR_SERVERFAILED;
                    break;
            }
            break;
        }

        if (strcmp(ans->dnsa4_qname, ans->dnsa4_cname) != 0) {
            evdns_server_request_add_cname_reply(req, ans->dnsa4_qname, ans->dnsa4_cname, ans->dnsa4_ttl);
        }

        for (uint16_t j = 0; j < ans->dnsa4_nrr; ++j) {
            in_addr_t orig_addr = ans->dnsa4_addr[j].s_addr;
            in_addr_t nat_addr = nt_reverse_lookup(orig_addr);
            ipset_add(data->ipset, orig_addr);

            ret = evdns_server_request_add_a_reply(req, ans->dnsa4_cname, 1, &nat_addr, ans->dnsa4_ttl);
            if (ret < 0) {
                err = DNS_ERR_SERVERFAILED;
                break;
            }
        }

        free(ans);
    }

    evdns_server_request_respond(req, err);
}

void dns_loop(uint16_t port, char *upstream_dns, char *ipset) {
    struct event_base *base;
    struct evdns_server_port *server;
    evutil_socket_t server_fd;
    struct sockaddr_in listenaddr;
    struct dns_ctx *ctx = &dns_defctx;

    dns_reset(ctx);
    dns_add_serv(ctx, upstream_dns);
    if (dns_open(ctx) < 0) {
        perror("dns_open");
        exit(EXIT_FAILURE);
    }

    base = event_base_new();
    if (!base) {
        perror("dns_loop: event_base_new");
        exit(EXIT_FAILURE);
    }

    server_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (server_fd < 0) {
        perror("dns_loop: socket");
        exit(EXIT_FAILURE);
    }

    memset(&listenaddr, 0, sizeof(listenaddr));
    listenaddr.sin_family = AF_INET;
    listenaddr.sin_port = htons(port);
    listenaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (bind(server_fd, (struct sockaddr *) &listenaddr, sizeof(listenaddr)) < 0) {
        perror("dns_loop: bind");
        exit(EXIT_FAILURE);
    }

    if (evutil_make_socket_nonblocking(server_fd) < 0) {
        perror("dns_loop: evutil_make_socket_nonblocking");
        exit(EXIT_FAILURE);
    }

    struct cb_data data = {ctx, ipset};
    server = evdns_add_server_port_with_base(base, server_fd, 0, server_cb, &data);

    event_base_dispatch(base);

    evdns_close_server_port(server);
    event_base_free(base);
}
