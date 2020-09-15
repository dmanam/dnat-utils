#ifndef __DBUS_H__
#define __DBUS_H__

#include <pthread.h>

void dbus_init(char *, pthread_t *);
void dbus_await(void);

#endif
