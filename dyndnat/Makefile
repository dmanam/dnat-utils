SOURCES := \
	main.c \
	conntrack.c \
	inotify.c \
	nat_table.c \
	nfqueue.c \
	rtnl.c

LIBS := -pthread -lmnl -lnetfilter_conntrack -lnetfilter_queue

OUTPUT := dyndnat

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
