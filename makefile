

CC=gcc -g

CFLAGS=-I. -I/usr/local/include/hiredis -std=gnu99 -O0 -D_GNU_SOURCE -Wall -lhiredis
DEPS = socket_op.h redis_thread.h
OBJS = main_loop.c socket_op.c redis_thread.c

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

wificam-scaner: $(OBJS)
	$(CC) -o $@ $^ $(CFLAGS)

.PHONY: clean
clean:
	rm -f ./*.o ./wificam-scaner