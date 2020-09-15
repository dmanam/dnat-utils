#ifndef __RTNL_H__
#define __RTNL_H__

#include <pthread.h>

int rtnl_init(unsigned char, char *);
void rtnl_update(void);

extern pthread_mutex_t _rtnl_mutex;
static inline void rtnl_lock(void) {
    pthread_mutex_lock(&_rtnl_mutex);
}
static inline void rtnl_unlock(void) {
    pthread_mutex_unlock(&_rtnl_mutex);
}

#endif
