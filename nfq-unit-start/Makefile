SOURCES := \
	main.c \
	dbus.c \
	nfqueue.c

LIBS := -pthread -lsystemd -lmnl -lnetfilter_queue

OUTPUT := nfq-unit-start

PREFIX ?= /usr/local

CFLAGS := -Wall

all: CFLAGS += -O2 -Werror
all: $(OUTPUT)

debug: CFLAGS += -g -O0 -DDEBUG
debug: $(OUTPUT)-debug

$(OUTPUT) $(OUTPUT)-debug: $(SOURCES)
	$(CC) -o $@ $(CFLAGS) $(LIBS) $(SOURCES)

install: all
	install -D -t "$(PREFIX)/bin" $(OUTPUT)

clean:
	rm -f $(OUTPUT) $(OUTPUT)-debug

.PHONY: all debug install clean
