CC=gcc
CFLAGS=-std=c99 -O2 -Wall -Wextra -Wpedantic -D_XOPEN_SOURCE=700
LDFLAGS=-lcrypto

OBJS=main.o crc32.o flash.o pagefmt.o crypto.o ftl.o snapshot.o

all: ftl_demo

ftl_demo: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f *.o ftl_demo
