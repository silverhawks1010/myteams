CC = gcc
CFLAGS = -Wall -Wextra -Werror
LDFLAGS = -pthread

all: server client

server: server.c
	$(CC) $(CFLAGS) server.c $(LDFLAGS) -o server

client: client.c
	$(CC) $(CFLAGS) client.c $(LDFLAGS) -o client

clean:
	rm -f server client

.PHONY: all clean
