#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>

#include "dbus.h"
#include "nfqueue.h"

int main(int argc, char *argv[]) {
    unsigned int queue_num;
    pthread_t dbus_thread;

    if (argc != 3) {
        goto usage;
    }

    char *endptr = NULL;
    queue_num = (unsigned int) strtoul(argv[1], &endptr, 10);
    if (argv[1][0] == '\0' || *endptr != '\0') {
        goto usage;
    }

    dbus_init(argv[2], &dbus_thread);

    return nfq_loop(queue_num);

usage:
    fprintf(stderr, "usage: %s <queue number> <systemd unit name>\n", argv[0]);
    exit(EXIT_FAILURE);
}
