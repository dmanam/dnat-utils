#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>

#include <systemd/sd-bus.h>

static char *unit_name = NULL;

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t activated = PTHREAD_COND_INITIALIZER;
static bool active = false;
static char last_state[16] = {0};

void dbus_await(void) {
    pthread_mutex_lock(&mutex);
    if (active) {
        pthread_mutex_unlock(&mutex);
        return;
    }
    pthread_mutex_unlock(&mutex);

    if (!unit_name) {
        fprintf(stderr, "error: dbus_await called before dbus_init");
        exit(EXIT_FAILURE);
    }

    int ret;
    sd_bus *bus;
    sd_bus_error err = SD_BUS_ERROR_NULL;
    sd_bus_message *msg;

    fprintf(stderr, "starting %s...\n", unit_name);

    sd_bus_default_system(&bus);
    ret = sd_bus_call_method(bus, "org.freedesktop.systemd1", "/org/freedesktop/systemd1", \
        "org.freedesktop.systemd1.Manager", "StartUnit", &err, &msg, "ss", unit_name, "replace");
    if (ret < 0) {
        fprintf(stderr, "org.freedesktop.systemd1.Manager.StartUnit: %s\n", err.message);
        exit(EXIT_FAILURE);
    }
    sd_bus_message_unref(msg);
    sd_bus_unref(bus);

    pthread_mutex_lock(&mutex);
    while (!active) {
        pthread_cond_wait(&activated, &mutex);
    }
    pthread_mutex_unlock(&mutex);
}

static void dbus_update_state(char *state) {
    bool b_state;

    if (strncmp(state, last_state, sizeof(last_state)) == 0) {
        return;
    }

    fprintf(stderr, "%s %s\n", unit_name, state);
    strncpy(last_state, state, sizeof(last_state));

    if (strcmp(state, "active") == 0) {
        b_state = true;
    } else if (strcmp(state, "inactive") == 0 || strcmp(state, "failed") == 0) {
        b_state = false;
    } else {
        return;
    }

    pthread_mutex_lock(&mutex);

    active = b_state;

    if (active) {
        pthread_cond_broadcast(&activated);
    }

    pthread_mutex_unlock(&mutex);
}

static int dbus_cb(sd_bus_message *msg, void *data, sd_bus_error *ret_error) {
    (void) data, (void) ret_error;
    int ret;
    char *state;

    ret = sd_bus_message_skip(msg, "s");
    if (ret < 0) {
        fprintf(stderr, "sd_bus_message_skip (s): %s\n", strerror(-ret));
        return -1;
    }

    ret = sd_bus_message_enter_container(msg, 'a', "{sv}");
    if (ret < 0) {
        fprintf(stderr, "sd_bus_enter_container (a): %s\n", strerror(-ret));
        return -1;
    }

    while (true) {
        char *prop;

        ret = sd_bus_message_peek_type(msg, NULL, NULL);
        if (ret == 0) {
            return 0;
        } else if (ret < 0) {
            fprintf(stderr, "sd_bus_peek_type: %s\n", strerror(-ret));
            return -1;
        }

        ret = sd_bus_message_enter_container(msg, 'e', "sv");
        if (ret < 0) {
            fprintf(stderr, "sd_bus_enter_container (e): %s\n", strerror(-ret));
            return -1;
        }

        ret = sd_bus_message_read(msg, "s", &prop);
        if (ret < 0) {
            fprintf(stderr, "sd_bus_message_read: %s\n", strerror(-ret));
            return -1;
        }

        if (strcmp(prop, "ActiveState") == 0) {
            break;
        }

        ret = sd_bus_message_skip(msg, "v");
        if (ret < 0) {
            fprintf(stderr, "sd_bus_message_skip (v): %s\n", strerror(-ret));
            return -1;
        }

        ret = sd_bus_message_exit_container(msg);
        if (ret < 0) {
            fprintf(stderr, "sd_bus_exit_container (e): %s\n", strerror(-ret));
            return -1;
        }
    }

    ret = sd_bus_message_enter_container(msg, 'v', "s");
    if (ret < 0) {
        fprintf(stderr, "sd_bus_enter_container (v): %s\n", strerror(-ret));
        return -1;
    }

    ret = sd_bus_message_read(msg, "s", &state);
    if (ret < 0) {
        fprintf(stderr, "sd_bus_message_read: %s\n", strerror(-ret));
        return -1;
    }

    dbus_update_state(state);

    return 0;
}

static void *dbus_loop(void *data) {
    sd_bus *bus = (sd_bus *) data;
    int ret;

    while (true) {
        ret = sd_bus_wait(bus, UINT64_MAX);
        if (ret < 0) {
            fprintf(stderr, "sd_bus_wait: %s\n", strerror(-ret));
        }

        ret = 1;
        while(ret > 0) {
            ret = sd_bus_process(bus, NULL);
            if (ret < 0) {
                fprintf(stderr, "sd_bus_process: %s\n", strerror(-ret));
            }
        }
    }

    sd_bus_unref(bus);
    return NULL;
}

void dbus_init(char *name, pthread_t *forked_thread) {
    int ret;
    sd_bus *bus;
    sd_bus_error err = SD_BUS_ERROR_NULL;
    sd_bus_message *msg;
    char *unit_path, *state;

    unit_name = strdup(name);

    ret = sd_bus_open_system(&bus);
    if (ret < 0) {
        fprintf(stderr, "sd_bus_open_system: %s\n", strerror(-ret));
        exit(EXIT_FAILURE);
    }

    ret = sd_bus_call_method(bus, "org.freedesktop.systemd1", "/org/freedesktop/systemd1", \
        "org.freedesktop.systemd1.Manager", "LoadUnit", &err, &msg, "s", unit_name);
    if (ret < 0) {
        fprintf(stderr, "org.freedesktop.systemd1.Manager.LoadUnit: %s\n", err.message);
        exit(EXIT_FAILURE);
    }

    ret = sd_bus_message_read(msg, "o", &unit_path);
    if (ret < 0) {
        fprintf(stderr, "sd_bus_message_read: %s\n", strerror(-ret));
        exit(EXIT_FAILURE);
    }

    char *rule_fmt = "sender=org.freedesktop.systemd1,path=%s,interface=org.freedesktop.DBus.Properties,member=PropertiesChanged,type=signal,arg0=org.freedesktop.systemd1.Unit";
    char *rule = malloc(strlen(rule_fmt) + strlen(unit_path) - 1);
    if (!rule) {
        perror("dbus_init: malloc");
        exit(EXIT_FAILURE);
    }
    sprintf(rule, rule_fmt, unit_path);
    ret = sd_bus_add_match(bus, NULL, rule, dbus_cb, NULL);
    if (ret < 0) {
        fprintf(stderr, "sd_bus_add_match: %s\n", strerror(-ret));
        exit(EXIT_FAILURE);
    }
    free(rule);

    ret = sd_bus_get_property_string(bus, "org.freedesktop.systemd1", unit_path, "org.freedesktop.systemd1.Unit", "ActiveState", &err, &state);
    if (ret < 0) {
        fprintf(stderr, "sd_bus_get_property_string org.freedesktop.systemd1.Unit.ActiveState: %s\n", err.message);
        exit(EXIT_FAILURE);
    }
    dbus_update_state(state);
    free(state);

    ret = pthread_create(forked_thread, NULL, dbus_loop, bus);
    if (ret != 0) {
        fprintf(stderr, "pthread_create: %s\n", strerror(ret));
        exit(EXIT_FAILURE);
    }
}
