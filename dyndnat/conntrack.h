#ifndef __CONNTRACK_H__
#define __CONTRACK_H__

#include <stdint.h>

int nfct_init(void);
void nfct_cleanup(void);
int nfct_add(uint8_t *);

#endif
