#ifndef __NAT_TABLE_H__
#define __NAT_TABLE_H__

#include <arpa/inet.h>

int nt_init(char *);
in_addr_t nt_lookup(in_addr_t);
in_addr_t nt_reverse_lookup(in_addr_t);

#endif
