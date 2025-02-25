#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <time.h>

/**
 * Maximum number of clients that can connect simultaneously
 */
#define MAX_CLIENTS 100

/**
 * Size of the buffer used for message transmission
 */
#define BUFFER_SIZE 1024

/**
 * Path to the log file where all messages are stored
 */
#define LOG_FILE "conversations.log"

/**
 * Maximum length of a status message
 */
#define STATUS_LENGTH 128

/**
 * Structure representing a connected client
 */
typedef struct {
    int socket;             /** Socket file descriptor */
    char username[50];      /** Client's username */
    char status[STATUS_LENGTH]; /** Client's current status message */
    int is_admin;          /** Whether this client is an admin (first to connect) */
} client_t;

/**
 * Structure containing server information
 */
typedef struct {
    time_t start_time;      /** Server start timestamp */
    int max_clients_ever;   /** Maximum number of simultaneous connections */
    char server_ip[16];     /** Server's IP address */
    int server_port;        /** Server's port number */
} server_info_t;

client_t clients[MAX_CLIENTS];
int client_count = 0;
pthread_mutex_t clients_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;
server_info_t server_info;

/**
 * Logs a message to the log file
 * @param message The message to log
 */
void log_message(const char *message) {
    pthread_mutex_lock(&log_mutex);
    FILE *log_file = fopen(LOG_FILE, "a");
    if (log_file != NULL) {
        fprintf(log_file, "%s", message);
        fclose(log_file);
    }
    pthread_mutex_unlock(&log_mutex);
}

/**
 * Sends the list of connected users to a client
 * @param client_socket Socket of the client to send the list to
 * @param new_user Username of the newly connected user
 */
void send_user_list(int client_socket, const char *new_user) {
    char user_list[BUFFER_SIZE] = "Hello ";
    strcat(user_list, new_user);
    strcat(user_list, "\nConnected users:\n");
    
    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < client_count; i++) {
        if (clients[i].socket != client_socket) {
            strcat(user_list, "- ");
            strcat(user_list, clients[i].username);
            if (clients[i].is_admin) strcat(user_list, "(*)");
            if (clients[i].status[0] != '\0') {
                strcat(user_list, " (");
                strcat(user_list, clients[i].status);
                strcat(user_list, ")");
            }
            strcat(user_list, "\n");
        }
    }
    pthread_mutex_unlock(&clients_mutex);
    
    send(client_socket, user_list, strlen(user_list), 0);
}

/**
 * Updates the maximum number of simultaneous clients
 */
void update_max_clients() {
    if (client_count > server_info.max_clients_ever) {
        server_info.max_clients_ever = client_count;
    }
}

/**
 * Handles the /info command, sending server information to the client
 * @param client_socket Socket of the requesting client
 */
void handle_info_command(int client_socket) {
    char info_message[BUFFER_SIZE];
    time_t current_time = time(NULL);
    long uptime = current_time - server_info.start_time;
    int hours = uptime / 3600;
    int minutes = (uptime % 3600) / 60;
    int seconds = uptime % 60;

    snprintf(info_message, BUFFER_SIZE,
        "\n=== Server Information ===\n"
        "IP: %s\n"
        "Port: %d\n"
        "Uptime: %02d:%02d:%02d\n"
        "Max users ever connected: %d\n"
        "Currently connected users (%d):\n",
        server_info.server_ip,
        server_info.server_port,
        hours, minutes, seconds,
        server_info.max_clients_ever,
        client_count);

    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < client_count; i++) {
        strcat(info_message, "- ");
        strcat(info_message, clients[i].username);
        if (clients[i].is_admin) strcat(info_message, "(*)");
        if (clients[i].status[0] != '\0') {
            strcat(info_message, " (");
            strcat(info_message, clients[i].status);
            strcat(info_message, ")");
        }
        strcat(info_message, "\n");
    }
    pthread_mutex_unlock(&clients_mutex);
    
    send(client_socket, info_message, strlen(info_message), 0);
}

/**
 * Broadcasts a message to all connected clients except the sender
 * @param message Message content to broadcast
 * @param sender_socket Socket of the sending client
 */
void broadcast_message(const char *message, int sender_socket) {
    char username[50] = "";
    char status[STATUS_LENGTH] = "";
    int is_admin = 0;
    char formatted_msg[BUFFER_SIZE];

    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < client_count; i++) {
        if (clients[i].socket == sender_socket) {
            strncpy(username, clients[i].username, sizeof(username) - 1);
            strncpy(status, clients[i].status, sizeof(status) - 1);
            is_admin = clients[i].is_admin;
            break;
        }
    }
    pthread_mutex_unlock(&clients_mutex);

    if (status[0] != '\0') {
        snprintf(formatted_msg, BUFFER_SIZE, "# %s%s (%s) > %s\n", 
                username, 
                is_admin ? "(*)" : "", 
                status, 
                message);
    } else {
        snprintf(formatted_msg, BUFFER_SIZE, "# %s%s > %s\n", 
                username, 
                is_admin ? "(*)" : "", 
                message);
    }

    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < client_count; i++) {
        if (clients[i].socket != sender_socket) {
            write(clients[i].socket, formatted_msg, strlen(formatted_msg));
        }
    }
    pthread_mutex_unlock(&clients_mutex);

    log_message(formatted_msg);
}

/**
 * Kicks a user from the server (admin only)
 * @param admin_socket Socket of the admin requesting the kick
 * @param username Username of the user to kick
 */
void kick_user(int admin_socket, const char *username) {
    int found = 0;
    char kick_msg[BUFFER_SIZE];
    char admin_name[50] = "";
    
    pthread_mutex_lock(&clients_mutex);
    
    int is_admin = 0;
    for (int i = 0; i < client_count; i++) {
        if (clients[i].socket == admin_socket) {
            is_admin = clients[i].is_admin;
            strncpy(admin_name, clients[i].username, sizeof(admin_name) - 1);
            break;
        }
    }
    
    if (!is_admin) {
        pthread_mutex_unlock(&clients_mutex);
        snprintf(kick_msg, BUFFER_SIZE, "You are not an admin!\n");
        write(admin_socket, kick_msg, strlen(kick_msg));
        return;
    }
    
    for (int i = 0; i < client_count; i++) {
        if (strcmp(clients[i].username, username) == 0) {
            found = 1;
            
            if (clients[i].is_admin) {
                pthread_mutex_unlock(&clients_mutex);
                snprintf(kick_msg, BUFFER_SIZE, "Cannot kick another admin!\n");
                write(admin_socket, kick_msg, strlen(kick_msg));
                return;
            }
            
            snprintf(kick_msg, BUFFER_SIZE, "# %s has been kicked by admin %s\n", username, admin_name);
            for (int j = 0; j < client_count; j++) {
                write(clients[j].socket, kick_msg, strlen(kick_msg));
            }
            
            close(clients[i].socket);
            log_message(kick_msg);
            
            for (int j = i; j < client_count - 1; j++) {
                clients[j] = clients[j + 1];
            }
            client_count--;
            break;
        }
    }
    
    pthread_mutex_unlock(&clients_mutex);
    
    if (!found) {
        snprintf(kick_msg, BUFFER_SIZE, "User %s not found\n", username);
        write(admin_socket, kick_msg, strlen(kick_msg));
    }
}

/**
 * Removes a client from the server
 * @param socket Socket of the client to remove
 */
void remove_client(int socket) {
    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < client_count; i++) {
        if (clients[i].socket == socket) {
            for (int j = i; j < client_count - 1; j++) {
                clients[j] = clients[j + 1];
            }
            client_count--;
            break;
        }
    }
    pthread_mutex_unlock(&clients_mutex);
}

/**
 * Gets the current status of a client
 * @param client_socket Socket of the client requesting their status
 */
void get_client_status(int client_socket) {
    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < client_count; i++) {
        if (clients[i].socket == client_socket) {
            char status_msg[BUFFER_SIZE];
            if (clients[i].status[0] != '\0') {
                snprintf(status_msg, BUFFER_SIZE, "Your current status: %s\n", clients[i].status);
            } else {
                snprintf(status_msg, BUFFER_SIZE, "You have no status set.\n");
            }
            write(client_socket, status_msg, strlen(status_msg));
            break;
        }
    }
    pthread_mutex_unlock(&clients_mutex);
}

/**
 * Updates a client's status and broadcasts the change
 * @param client_socket Socket of the client updating their status
 * @param status New status message
 */
void update_client_status(int client_socket, const char *status) {
    char username[50] = "";
    char status_msg[BUFFER_SIZE];

    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < client_count; i++) {
        if (clients[i].socket == client_socket) {
            strncpy(username, clients[i].username, sizeof(username) - 1);
            strncpy(clients[i].status, status, STATUS_LENGTH - 1);
            clients[i].status[STATUS_LENGTH - 1] = '\0';
            break;
        }
    }
    pthread_mutex_unlock(&clients_mutex);

    snprintf(status_msg, BUFFER_SIZE, "# %s changed its status:\n%s\n", username, status);

    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < client_count; i++) {
        write(clients[i].socket, status_msg, strlen(status_msg));
    }
    pthread_mutex_unlock(&clients_mutex);

    log_message(status_msg);
}

/**
 * Thread function to handle a connected client
 * @param arg Pointer to the client socket
 * @return NULL
 */
void *handle_client(void *arg) {
    int client_socket = *(int*)arg;
    char buffer[BUFFER_SIZE];
    free(arg);

    memset(buffer, 0, BUFFER_SIZE);
    int bytes_read = recv(client_socket, buffer, BUFFER_SIZE - 1, 0);
    if (bytes_read <= 0) {
        close(client_socket);
        return NULL;
    }
    buffer[bytes_read] = '\0';

    pthread_mutex_lock(&clients_mutex);
    strncpy(clients[client_count].username, buffer, 49);
    clients[client_count].status[0] = '\0';
    clients[client_count].socket = client_socket;
    clients[client_count].is_admin = (client_count == 0);
    client_count++;
    update_max_clients();
    pthread_mutex_unlock(&clients_mutex);

    send_user_list(client_socket, buffer);

    while (1) {
        memset(buffer, 0, BUFFER_SIZE);
        bytes_read = recv(client_socket, buffer, BUFFER_SIZE - 1, 0);
        if (bytes_read <= 0) {
            break;
        }
        buffer[bytes_read] = '\0';

        if (strcmp(buffer, "/status") == 0) {
            get_client_status(client_socket);
        } else if (strncmp(buffer, "/status ", 8) == 0) {
            update_client_status(client_socket, buffer + 8);
        } else if (strcmp(buffer, "/info") == 0) {
            handle_info_command(client_socket);
        } else if (strncmp(buffer, "/kick ", 6) == 0) {
            kick_user(client_socket, buffer + 6);
        } else {
            broadcast_message(buffer, client_socket);
        }
    }

    remove_client(client_socket);
    close(client_socket);
    return NULL;
}

/**
 * Main server function
 * @param argc Argument count
 * @param argv Argument vector
 * @return 0 on success, 1 on error
 */
int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <port>\n", argv[0]);
        return 1;
    }

    FILE *log_file = fopen(LOG_FILE, "a");
    if (log_file == NULL) {
        perror("Could not open log file");
        return 1;
    } else {
        fclose(log_file);
    }

    server_info.start_time = time(NULL);
    server_info.max_clients_ever = 0;
    strcpy(server_info.server_ip, "0.0.0.0");
    server_info.server_port = atoi(argv[1]);

    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == -1) {
        perror("Socket creation failed");
        return 1;
    }

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server_info.server_port);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    int opt = 1;
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt failed");
        return 1;
    }

    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        return 1;
    }

    if (listen(server_socket, 5) < 0) {
        perror("Listen failed");
        return 1;
    }

    printf("Server reachable on IP %s port %d\n", server_info.server_ip, server_info.server_port);
    printf("Waiting for new clients...\n");

    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int *client_socket = malloc(sizeof(int));
        *client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_len);
        
        if (*client_socket < 0) {
            perror("Accept failed");
            free(client_socket);
            continue;
        }

        pthread_t thread;
        if (pthread_create(&thread, NULL, handle_client, (void*)client_socket) < 0) {
            perror("Could not create thread");
            free(client_socket);
            continue;
        }
        pthread_detach(thread);
    }

    close(server_socket);
    return 0;
}
