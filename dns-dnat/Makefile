SOURCES := \
	main.c \
	conntrack.c \
	dns.c \
	ipset.c \
	nat_table.c \
	nfqueue.c

LIBS := -pthread -ludns -levent -lmnl -lnetfilter_conntrack -lnetfilter_queue

OUTPUT := dns-dnat

PREFIX ?= /usr/local

CFLAGS := -Wall

all: CFLAGS += -O2
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
