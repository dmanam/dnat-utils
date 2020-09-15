#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>

#include <sys/inotify.h>

#include "nat_table.h"
#include "rtnl.h"

void in_watch(char *fp) {
    int fd, wd;
    uint32_t mask = IN_MODIFY | IN_DELETE_SELF | IN_MOVE_SELF;
    struct inotify_event ev;

    fd = inotify_init();
    wd = inotify_add_watch(fd, fp, mask);
    if (wd == -1) {
        perror("inotify_add_watch");
        exit(EXIT_FAILURE);
    }

    while (true) {
        if (read(fd, &ev, sizeof(struct inotify_event)) == -1) {
            perror("in_watch: read");
            exit(EXIT_FAILURE);
        }
        if (ev.wd != wd) {
            continue;
        }
        if (ev.mask & (IN_DELETE_SELF | IN_MOVE_SELF | IN_IGNORED)) {
            // in case the file was edited with something like vim
            usleep(100000);
            wd = inotify_add_watch(fd, fp, mask);
            if (wd == -1) {
                if (errno == ENOENT) {
                    fprintf(stderr, "watched file `%s' removed\n", fp);
                    exit(EXIT_FAILURE);
                } else {
                    perror("inotify_add_watch");
                    exit(EXIT_FAILURE);
                }
            }
        }
        nt_read(fp);
        rtnl_update();
    }
}
