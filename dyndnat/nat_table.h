#ifndef __NAT_TABLE_H__
#define __NAT_TABLE_H__

#include <arpa/inet.h>

int nt_read(char *);
in_addr_t nt_lookup(in_addr_t);

#endif
