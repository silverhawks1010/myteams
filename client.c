#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pthread.h>
#include <stdbool.h>

/**
 * Size of the buffer used for message transmission
 */
#define BUFFER_SIZE 1024

/**
 * Maximum length of a status message
 */
#define STATUS_LENGTH 128

/**
 * Global state for Do Not Disturb mode
 */
bool pause_mode = false;

/**
 * Current user's status message
 */
char current_status[STATUS_LENGTH] = "";

/**
 * Displays help information about available commands
 */
void print_help() {
    printf("\nAvailable commands:\n");
    printf("/status [message] - View or set your status\n");
    printf("/info            - Show server information\n");
    printf("/pause           - Toggle Do Not Disturb mode\n");
    printf("/kick <username> - (Admin only) Kick a user from the server\n");
    printf("/help            - Show this help message\n\n");
}

/**
 * Thread function to handle receiving messages from server
 * @param socket_desc Pointer to socket file descriptor
 * @return NULL
 */
void *receive_handler(void *socket_desc) {
    int sock = *(int*)socket_desc;
    char buffer[BUFFER_SIZE];
    int first_message = 1;
    
    while (1) {
        memset(buffer, 0, BUFFER_SIZE);
        ssize_t bytes_read = read(sock, buffer, BUFFER_SIZE - 1);
        if (bytes_read <= 0) {
            printf("\nServer disconnected\n");
            exit(1);
        }
        buffer[bytes_read] = '\0';

        // First message is the user list
        if (first_message) {
            printf("%s", buffer);
            first_message = 0;
        } else {
            // Clear current line and print message
            printf("\r\033[K%s", buffer);
        }
        
        // Always show prompt after any message
        printf("Send a new message: ");
        fflush(stdout);
    }
    return NULL;
}

/**
 * Main client function
 * @param argc Argument count
 * @param argv Argument vector (server_ip, port, username)
 * @return 0 on success, 1 on error
 */
int main(int argc, char *argv[]) {
    if (argc != 4) {
        printf("Usage: %s <server_ip> <port> <username>\n", argv[0]);
        return 1;
    }

    const char *server_ip = argv[1];
    int port = atoi(argv[2]);
    const char *username = argv[3];

    int client_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (client_socket == -1) {
        perror("Socket creation failed");
        return 1;
    }

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    
    if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0) {
        printf("Invalid address or address not supported\n");
        return 1;
    }

    printf("Connection to server... ");
    if (connect(client_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        printf("Failed\n");
        perror("Connection failed");
        return 1;
    }
    printf("OK.\n");

    // Send initial username to server
    write(client_socket, username, strlen(username));

    // Create thread for receiving messages
    pthread_t recv_thread;
    if (pthread_create(&recv_thread, NULL, receive_handler, (void*)&client_socket) < 0) {
        perror("Could not create receive thread");
        return 1;
    }

    char message[BUFFER_SIZE];
    while (1) {
        printf("Send a new message: ");
        fflush(stdout);
        
        if (fgets(message, BUFFER_SIZE, stdin) == NULL) {
            break;
        }
        
        message[strcspn(message, "\n")] = 0;

        // Handle commands
        if (strcmp(message, "/help") == 0) {
            print_help();
            continue;
        } else if (strcmp(message, "/pause") == 0) {
            pause_mode = !pause_mode;
            printf("Do Not Disturb mode: %s\n", pause_mode ? "ON" : "OFF");
            continue;
        } else if (strcmp(message, "/status") == 0 || strncmp(message, "/status ", 8) == 0) {
            if (strncmp(message, "/status ", 8) == 0) {
                strncpy(current_status, message + 8, STATUS_LENGTH - 1);
                current_status[STATUS_LENGTH - 1] = '\0';
            }
            write(client_socket, message, strlen(message));
            continue;
        } else if (strcmp(message, "/info") == 0) {
            write(client_socket, message, strlen(message));
            continue;
        } else if (strncmp(message, "/kick ", 6) == 0) {
            write(client_socket, message, strlen(message));
            continue;
        }

        if (!pause_mode) {
            // Show message locally with admin star if first client
            if (current_status[0] != '\0') {
                printf("# %s%s (me) (%s) > %s\n", 
                    username, 
                    client_socket == 1 ? "(*)" : "",  // First client is admin
                    current_status, 
                    message);
            } else {
                printf("# %s%s (me) > %s\n", 
                    username,
                    client_socket == 1 ? "(*)" : "",  // First client is admin
                    message);
            }

            // Send raw message to server
            write(client_socket, message, strlen(message));
        }
    }

    close(client_socket);
    pthread_cancel(recv_thread);
    pthread_join(recv_thread, NULL);
    return 0;
}
