#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <pthread.h>

#include <arpa/inet.h>

static uint32_t *keys;
static in_addr_t *vals;
static uint16_t *bins = NULL;

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

void nt_vals_iter(const in_addr_t **ret_vals, uint16_t *ret_len) {
    pthread_mutex_lock(&mutex);
    *ret_vals = vals;
    *ret_len = bins[257];
}

void nt_vals_iter_end(void) {
    pthread_mutex_unlock(&mutex);
}

int nt_read(char *fp) {
    FILE* file;
    uint32_t *old_keys = keys, *new_keys = NULL, *tmp_keys = NULL;
    in_addr_t *old_vals = vals, *new_vals = NULL, *tmp_vals = NULL;
    uint16_t *old_bins = bins, *new_bins = NULL, *sorted_order = NULL;
    uint16_t nlines;

    file = fopen(fp, "r");
    if (!file) {
        perror("nt_read: fopen");
        goto nt_read_failure;
    }

    nlines = 0;
    for (int chr; (chr = getc(file)) != EOF;) {
        if (chr == ',') {
            ++nlines;
        }
    }
    if (ferror(file)) {
        perror("nt_read: getc");
        goto nt_read_failure;
    }
    rewind(file);

    tmp_keys = malloc(nlines * sizeof(uint32_t));
    tmp_vals = malloc(nlines * sizeof(uint32_t));
    sorted_order = malloc(nlines * sizeof(uint16_t));
    if (!tmp_keys || !tmp_vals || !sorted_order) {
        perror("nt_read: malloc");
        goto nt_read_failure;
    }

    char buf[16];
    uint8_t buf_idx = 0, coln = 0;
    uint16_t line_idx = 0;
    for (int chr; (chr = getc(file)) != EOF;) {
        if (chr == ' ' || chr == '\t') {
            continue;
        }
        if (chr == ',' || chr == '\n') {
            buf[buf_idx] = '\0';
            in_addr_t addr_raw = inet_addr(buf);
            if (addr_raw == (in_addr_t) -1) {
                goto nt_read_parse_failure;
            }
            if (coln == 1) {
                tmp_vals[line_idx] = addr_raw;
                ++line_idx;
            } else {
                uint32_t addr = ntohl(addr_raw);
                uint16_t insert_idx = line_idx;
                for (; insert_idx > 0; --insert_idx) {
                    uint16_t idx = sorted_order[insert_idx-1];
                    int16_t cmp = (addr % 256) - (tmp_keys[idx] % 256);
                    if (cmp > 0 || (cmp == 0 && addr >= tmp_keys[idx])) {
                        if (addr == tmp_keys[idx]) {
                            addr = (uint32_t) -1;
                            insert_idx = line_idx;
                        }
                        break;
                    }
                }
                tmp_keys[line_idx] = addr;
                for (uint16_t i = line_idx; i > insert_idx; --i) {
                    sorted_order[i] = sorted_order[i-1];
                }
                sorted_order[insert_idx] = line_idx;
            }

            buf_idx = 0;
            coln = (coln + 1) % 2;
        } else if (buf_idx >= 15) {
            goto nt_read_parse_failure;
        } else {
            buf[buf_idx] = (char) chr;
            ++buf_idx;
        }
    }
    if (ferror(file)) {
        perror("nt_read: getc");
        goto nt_read_failure;
    }
    if (nlines != line_idx) {
        goto nt_read_parse_failure;
    }

    new_keys = malloc(nlines * sizeof(in_addr_t));
    new_vals = malloc(nlines * sizeof(in_addr_t));
    new_bins = malloc(258 * sizeof(uint16_t));
    if (!new_keys || !new_vals || !new_bins) {
        perror("nt_read: malloc");
        goto nt_read_failure;
    }

    {
        fprintf(stderr, "reading in new NAT table\n");
        char s_key[16], s_val[16];
        uint16_t next_bin = 0;
        for (uint16_t i = 0; i < nlines; ++i) {
            uint16_t idx = sorted_order[i];
            new_keys[i] = tmp_keys[idx];
            new_vals[i] = tmp_vals[idx];
            in_addr_t n_new_key = ntohl(new_keys[i]);
            inet_ntop(AF_INET,   &n_new_key, s_key, 16);
            inet_ntop(AF_INET, &new_vals[i], s_val, 16);
            if (new_keys[i] != (uint32_t) -1) {
                fprintf(stderr, "  mapping %s to %s\n", s_key, s_val);
                for (; next_bin <= tmp_keys[idx] % 256; ++next_bin) {
                    new_bins[next_bin] = i;
                }
            } else {
                fprintf(stderr, "  routing %s\n", s_val);
                for (; next_bin <= 257; ++next_bin) {
                    new_bins[next_bin] = i;
                }
            }
        }
        for (; next_bin <= 257; ++next_bin) {
            new_bins[next_bin] = nlines;
        }
    }

    free(tmp_keys);
    free(tmp_vals);
    free(sorted_order);

    fclose(file);

    pthread_mutex_lock(&mutex);

    keys = new_keys;
    vals = new_vals;
    bins = new_bins;

    pthread_mutex_unlock(&mutex);

    if (old_bins) {
        free(old_keys);
        free(old_vals);
        free(old_bins);
    }

    return 0;

nt_read_parse_failure:

    fprintf(stderr, "malformed data in file `%s'\n", fp);

    /* continue */

nt_read_failure:

    if (file) {
        fclose(file);
    }

    free(new_keys);
    free(new_vals);
    free(new_bins);

    free(tmp_keys);
    free(tmp_vals);

    if (old_bins != NULL) {
        fprintf(stderr, "error loading new NAT table, continuing with old one\n");
        return -1;
    } else {
        fprintf(stderr, "fatal error loading NAT table\n");
        exit(EXIT_FAILURE);
    }
}

in_addr_t nt_lookup(in_addr_t addr_raw) {
    in_addr_t ret = -1;

    uint32_t addr = ntohl(addr_raw);

    pthread_mutex_lock(&mutex);

    if (bins) {
        uint16_t bin = bins[addr % 256];
        uint16_t bin_next = bins[(addr % 256) + 1];

        uint16_t l = bin;
        uint16_t r = bin_next - 1;
        while (l <= r) {
            uint16_t m = (l + r) / 2;
            if (keys[m] == addr) {
                ret = vals[m];
                break;
            } else if (keys[m] < addr) {
                l = m + 1;
            } else {
                r = m - 1;
            }
        }
    }

    pthread_mutex_unlock(&mutex);

    return ret;
}
