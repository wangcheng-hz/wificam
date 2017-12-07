

CC=gcc

CFLAGS=-I. -std=c99 -Wall
DEPS = socket_op.h
OBJS = main_loop.c socket_op.c

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

all: $(OBJS)
	$(CC) -o $@ $^ $(CFLAGS)

.PHONY: clean
clean:
	rm -f ./*.o
