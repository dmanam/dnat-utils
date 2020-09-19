#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>

#include "dns.h"
#include "ipset.h"
#include "nat_table.h"
#include "nfqueue.h"

struct nfq_args {
  unsigned int queue_num;
  unsigned int fwmark;
};

void *nfq_loop_wrapper(void *data) {
    struct nfq_args *args = (struct nfq_args *) data;
    nfq_loop(args->queue_num, args->fwmark);
    return NULL;
}

int main(int argc, char **argv) {
    struct nfq_args nfq_args;
    uint16_t port;
    pthread_t nfq_thread;
    char *endptr = NULL;

    if (argc != 7) {
        goto usage;
    }

    endptr = NULL;
    nfq_args.queue_num = (unsigned int) strtoul(argv[1], &endptr, 10);
    if (argv[1][0] == '\0' || *endptr != '\0') {
        goto usage;
    }

    endptr = NULL;
    nfq_args.fwmark = (unsigned int) strtoul(argv[2], &endptr, 10);
    if (argv[2][0] == '\0' || *endptr != '\0') {
        goto usage;
    }

    endptr = NULL;
    port = (uint16_t) strtoul(argv[5], &endptr, 10);
    if (argv[5][0] == '\0' || *endptr != '\0') {
        goto usage;
    }

    nt_init(argv[3]);

    pthread_create(&nfq_thread, NULL, nfq_loop_wrapper, &nfq_args);

    dns_loop(port, argv[6], argv[4]);

    exit(EXIT_SUCCESS);

usage:
    fprintf(stderr, "usage: %s queue_num fwmark nat_range_cidr ipset dns_port upstream_dns\n", argv[0]);
    exit(EXIT_FAILURE);
}
