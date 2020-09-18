#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <pthread.h>

#include <arpa/inet.h>

#define HASH(x) (x >> 24)

struct index {
    uint8_t bin;
    uint16_t idx;
};

static in_addr_t *keys[256] = {0}, *vals[256] = {0};
static uint16_t bin_len[256] = {0};
static uint8_t bin_space[256] = {0};
static struct index *val_sort = NULL;
static uint8_t val_space = 0;
static uint32_t total_len = 0;

static uint32_t next_new_key;
static uint32_t max_key;
static uint32_t min_key;

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

void nt_init(char *cidr) {
    uint8_t b3, b2, b1, b0, bits;
    uint32_t mask;

    if (sscanf(cidr, "%hhu.%hhu.%hhu.%hhu/%hhu", &b3, &b2, &b1, &b0, &bits) < 5 || bits > 32) {
        fprintf(stderr, "failed to parse NAT range CIDR\n");
        exit(EXIT_FAILURE);
    }

    next_new_key = (b3 << 24UL) | (b2 << 16UL) | (b1 << 8UL) | b0;

    mask = (0xFFFFFFFFUL << (32 - bits)) & 0xFFFFFFFFUL;
    min_key = next_new_key & mask;
    max_key = next_new_key | (~mask);
}

static void _nt_add(in_addr_t key, in_addr_t val, bool lock) {
    uint16_t idx;
    uint8_t bin = HASH(key);
    char s_key[16], s_val[16];

    inet_ntop(AF_INET, &key, s_key, 16);
    inet_ntop(AF_INET, &val, s_val, 16);
    fprintf(stderr, "adding DNAT from %s to %s\n", s_key, s_val);

    if (lock) pthread_mutex_lock(&mutex);

    if (bin_space[bin] == 0) {
        keys[bin] = realloc(keys[bin], (bin_len[bin] + 2) * sizeof(in_addr_t));
        vals[bin] = realloc(vals[bin], (bin_len[bin] + 2) * sizeof(in_addr_t));
        if (!keys[bin] || !vals[bin]) {
            perror("nt_add: realloc");
            exit(EXIT_FAILURE);
        }
        bin_space[bin] = 2;
    }

    idx = 0;
    {
        int32_t l = 0, r = bin_len[bin] - 1;
        while (l <= r) {
            idx = (l + r) / 2;
            if (keys[bin][idx] == key) {
                vals[bin][idx] = val;
                goto val_sort;
            } else if (keys[bin][idx] < key) {
                l = idx + 1;
            } else {
                r = idx - 1;
            }
        }
        if (keys[bin][idx] < key) {
            ++idx;
        }
    }

    for (uint16_t i = bin_len[bin]; i > idx; --i) {
        keys[bin][i] = keys[bin][i-1];
        vals[bin][i] = vals[bin][i-1];
    }

    keys[bin][idx] = key;
    vals[bin][idx] = val;

val_sort:

    if (val_space == 0) {
        val_sort = realloc(val_sort, (total_len + 32) * sizeof(struct index));
        if (!val_sort) {
            perror("nt_add: realloc");
            exit(EXIT_FAILURE);
        }
        val_space = 31;
    }

    uint32_t val_idx = 0;
    if (total_len > 0) {
        int32_t l = 0, r = total_len - 1;
        struct index vi = {0, 0};
        while (l <= r) {
            val_idx = (l + r) / 2;
            vi = val_sort[val_idx];
            if (vals[vi.bin][vi.idx] <= val) {
                l = val_idx + 1;
            } else {
                r = val_idx - 1;
            }
        }
        if (vals[vi.bin][vi.idx] <= val) {
            ++val_idx;
        }
    }

    for (uint32_t i = total_len; i > val_idx; --i) {
        val_sort[i] = val_sort[i-1];
    }

    val_sort[val_idx] = (struct index){bin, idx};

    ++total_len;
    ++bin_len[bin];
    --bin_space[bin];

    if (lock) pthread_mutex_unlock(&mutex);
}

void nt_add(in_addr_t key, in_addr_t val) {
    _nt_add(key, val, true);
}

in_addr_t nt_lookup(in_addr_t key) {
    in_addr_t ret = (in_addr_t) -1;
    uint8_t bin = HASH(key);

    pthread_mutex_lock(&mutex);

    if (keys[bin]) {
        int32_t l = 0, r = bin_len[bin] - 1;
        while (l <= r) {
            uint16_t m = (l + r) / 2;
            if (keys[bin][m] == key) {
                ret = vals[bin][m];
                break;
            } else if (keys[bin][m] < key) {
                l = m + 1;
            } else {
                r = m - 1;
            }
        }
    }

    pthread_mutex_unlock(&mutex);

    return ret;
}

in_addr_t nt_reverse_lookup(in_addr_t val) {
    in_addr_t ret;

    pthread_mutex_lock(&mutex);

    if (val_sort) {
        int32_t l = 0, r = total_len - 1;
        while (l <= r) {
            uint32_t m = (l + r) / 2;
            struct index vi = val_sort[m];
            if (vals[vi.bin][vi.idx] == val) {
                ret = keys[vi.bin][vi.idx];
                goto finish;
            } else if (vals[vi.bin][vi.idx] < val) {
                l = m + 1;
            } else {
                r = m - 1;
            }
        }
    }

    if (next_new_key > max_key) {
        fprintf(stderr, "ran out of IP addresses; looping around\n");
        next_new_key = min_key;
    }

    ret = htonl(next_new_key);

    _nt_add(ret, val, false);

    ++next_new_key;

finish:
    pthread_mutex_unlock(&mutex);

    return ret;
}
