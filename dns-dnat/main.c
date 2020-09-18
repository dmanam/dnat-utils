#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>

#include "dns.h"
#include "ipset.h"
#include "nat_table.h"
#include "nfqueue.h"


void *nfq_loop_wrapper(void *queue_num) {
    nfq_loop(*((unsigned int *) queue_num));
    return NULL;
}

int main(int argc, char **argv) {
    unsigned int queue_num;
    uint16_t port;
    pthread_t nfq_thread;
    char *endptr = NULL;

    if (argc != 6) {
        goto usage;
    }

    endptr = NULL;
    queue_num = (unsigned int) strtoul(argv[1], &endptr, 10);
    if (argv[1][0] == '\0' || *endptr != '\0') {
        goto usage;
    }

    endptr = NULL;
    port = (uint16_t) strtoul(argv[4], &endptr, 10);
    if (argv[4][0] == '\0' || *endptr != '\0') {
        goto usage;
    }

    nt_init(argv[2]);

    pthread_create(&nfq_thread, NULL, nfq_loop_wrapper, &queue_num);

    dns_loop(port, argv[5], argv[3]);

    exit(EXIT_SUCCESS);

usage:
    fprintf(stderr, "usage: %s queue_num nat_range_cidr ipset dns_port upstream_dns\n", argv[0]);
    exit(EXIT_FAILURE);
}
