CC = gcc
CFLAGS = -Wall -Wextra -Werror
LDFLAGS = -pthread
RM = rm -f

SERVER_NAME = server
CLIENT_NAME = client

SERVER_SRC = server.c
CLIENT_SRC = client.c

SERVER_OBJ = $(SERVER_SRC:.c=.o)
CLIENT_OBJ = $(CLIENT_SRC:.c=.o)

all: $(SERVER_NAME) $(CLIENT_NAME)

$(SERVER_NAME): $(SERVER_OBJ)
	$(CC) $(SERVER_OBJ) $(LDFLAGS) -o $(SERVER_NAME)

$(CLIENT_NAME): $(CLIENT_OBJ)
	$(CC) $(CLIENT_OBJ) $(LDFLAGS) -o $(CLIENT_NAME)

clean:
	$(RM) $(SERVER_OBJ) $(CLIENT_OBJ)

fclean: clean
	$(RM) $(SERVER_NAME) $(CLIENT_NAME)

re: fclean all

.PHONY: all clean fclean re
