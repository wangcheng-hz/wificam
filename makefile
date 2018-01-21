

CC=gcc -g

CFLAGS=-I. -I/usr/local/include/hiredis -std=gnu99 -O0 -D_GNU_SOURCE -Wall -lhiredis -pthread
DEPS = socket_op.h redis_thread.h unix_server.h wificam_utility.h
OBJS = main_loop.c socket_op.c redis_thread.c unix_server.c wificam_utility.c

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

all: wificam-scaner wificamcli

wificam-scaner: $(OBJS)
	$(CC) -o $@ $^ $(CFLAGS)

wificamcli:
	$(CC) -O0 -Wall -I. wificamcli.c -o wificamcli

.PHONY: clean
clean:
	rm -f ./*.o ./wificam-scaner ./wificamcli
