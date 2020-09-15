#ifndef __NAT_TABLE_H__
#define __NAT_TABLE_H__

#include <arpa/inet.h>

int nt_read(char *);
in_addr_t nt_lookup(in_addr_t);
void nt_vals_iter(const in_addr_t **, uint16_t *);
void nt_vals_iter_end(void);

#endif
