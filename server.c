/**
 * @file server.c
 * @brief Serveur de chat multi-clients avec authentification
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <time.h>
#include <stdbool.h>

/**
 * @def MAX_CLIENTS
 * @brief Nombre maximum de clients pouvant se connecter simultanément
 */
#define MAX_CLIENTS 100

/**
 * @def BUFFER_SIZE
 * @brief Taille du buffer pour les messages
 */
#define BUFFER_SIZE 1024

/**
 * @def STATUS_LENGTH
 * @brief Longueur maximale d'un message de statut
 */
#define STATUS_LENGTH 128

/**
 * @def USERNAME_LENGTH
 * @brief Longueur maximale d'un nom d'utilisateur
 */
#define USERNAME_LENGTH 50

/**
 * @def PASSWORD_LENGTH
 * @brief Longueur maximale d'un mot de passe
 */
#define PASSWORD_LENGTH 50

/**
 * @def LOG_FILE
 * @brief Chemin du fichier de log
 */
#define LOG_FILE "conversations.log"

/**
 * @def USERS_FILE
 * @brief Chemin du fichier de configuration des utilisateurs
 */
#define USERS_FILE "users.conf"

/**
 * @struct user_auth_t
 * @brief Structure contenant les informations d'authentification d'un utilisateur
 */
typedef struct {
    char username[USERNAME_LENGTH];  /**< Nom d'utilisateur */
    char password[PASSWORD_LENGTH];  /**< Mot de passe */
} user_auth_t;

/**
 * @struct client_t
 * @brief Structure contenant les informations d'un client connecté
 */
typedef struct {
    int socket;                     /**< Socket du client */
    char username[USERNAME_LENGTH];  /**< Nom d'utilisateur */
    char status[STATUS_LENGTH];     /**< Statut actuel */
    int is_admin;                   /**< 1 si admin, 0 sinon */
    int is_authenticated;           /**< 1 si authentifié, 0 sinon */
} client_t;

/**
 * @struct server_info_t
 * @brief Structure contenant les informations du serveur
 */
typedef struct {
    time_t start_time;             /**< Heure de démarrage */
    int max_clients_ever;          /**< Nombre maximum de clients connectés */
    char server_ip[16];            /**< Adresse IP du serveur */
    int server_port;               /**< Port du serveur */
} server_info_t;

/** Variables globales */
client_t clients[MAX_CLIENTS];
int client_count = 0;
pthread_mutex_t clients_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;
server_info_t server_info;
user_auth_t registered_users[MAX_CLIENTS];
int registered_users_count = 0;

/**
 * @brief Écrit un message dans le fichier de log
 * @param message Message à logger
 */
void log_message(const char *message) {
    pthread_mutex_lock(&log_mutex);
    FILE *log_file = fopen(LOG_FILE, "a");
    if (log_file != NULL) {
        time_t now = time(NULL);
        char *date = ctime(&now);
        date[strlen(date) - 1] = '\0';
        fprintf(log_file, "[%s] %s", date, message);
        fclose(log_file);
    }
    pthread_mutex_unlock(&log_mutex);
}

/**
 * @brief Charge les utilisateurs depuis le fichier de configuration
 * @return 1 si succès, 0 si échec
 */
int load_users() {
    FILE *file = fopen(USERS_FILE, "r");
    if (!file) {
        perror("Error opening users configuration file");
        return 0;
    }

    char line[BUFFER_SIZE];
    while (fgets(line, sizeof(line), file) && registered_users_count < MAX_CLIENTS) {
        line[strcspn(line, "\n")] = 0;

        char *username = strtok(line, ":");
        char *password = strtok(NULL, ":");

        if (username && password) {
            strncpy(registered_users[registered_users_count].username, username, USERNAME_LENGTH - 1);
            strncpy(registered_users[registered_users_count].password, password, PASSWORD_LENGTH - 1);
            registered_users_count++;
        }
    }

    fclose(file);
    printf("Loaded %d users from configuration\n", registered_users_count);
    return 1;
}

/**
 * @brief Vérifie les credentials d'un utilisateur
 * @param username Nom d'utilisateur
 * @param password Mot de passe
 * @return 1 si authentification réussie, 0 sinon
 */
int authenticate_user(const char *username, const char *password) {
    for (int i = 0; i < registered_users_count; i++) {
        if (strcmp(registered_users[i].username, username) == 0 &&
            strcmp(registered_users[i].password, password) == 0) {
            return 1;
        }
    }
    return 0;
}

/**
 * @brief Vérifie si un utilisateur existe dans la configuration
 * @param username Nom du utilisateur à vérifier
 * @return 1 si l'utilisateur existe, 0 sinon
 */
int user_exists(const char *username) {
    for (int i = 0; i < registered_users_count; i++) {
        if (strcmp(registered_users[i].username, username) == 0) {
            return 1;
        }
    }
    return 0;
}

/**
 * @brief Envoie la liste des utilisateurs connectés à un client
 * @param client_socket Socket du client
 * @param new_user Nom du nouvel utilisateur
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
 * @brief Met à jour le nombre maximum de clients connectés
 */
void update_max_clients() {
    if (client_count > server_info.max_clients_ever) {
        server_info.max_clients_ever = client_count;
    }
}

/**
 * @brief Gère la commande /info
 * @param client_socket Socket du client demandant l'info
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
 * @brief Diffuse un message à tous les clients sauf l'expéditeur
 * @param message Message à diffuser
 * @param sender_socket Socket de l'expéditeur
 */
void broadcast_message(const char *message, int sender_socket) {
    char username[USERNAME_LENGTH] = "";
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
 * @brief Expulse un utilisateur du serveur (admin uniquement)
 * @param admin_socket Socket de l'admin
 * @param username Nom de l'utilisateur à expulser
 */
void kick_user(int admin_socket, const char *username) {
    int found = 0;
    char kick_msg[BUFFER_SIZE];
    char admin_name[USERNAME_LENGTH] = "";

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
 * @brief Supprime un client du serveur
 * @param socket Socket du client à supprimer
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
z * @brief Récupère le statut actuel d'un client
 * @param client_socket Socket du client
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
 * @brief Recois de la data et en créer un fichier en ajoutant l'extension .saved
 */
void receive_file(int client_socket, char* filename) {
    char buffer[BUFFER_SIZE];
    printf("Saving file %s\n", filename);
    strcat(filename, ".saved");

    FILE *file = fopen(filename, "wb");
    if (!file) {
        perror("Error while opening the file");
        return;
    }

    while (1) {
        ssize_t n = recv(client_socket, buffer, BUFFER_SIZE, 0);
        if (n <= 0) {
            if (n == 0) {
                printf("Connexion reset by the client\n");
            } else {
                perror("Error during reception\n");
            }
            break;
        }

        char *end_marker = strstr(buffer, "END"); // Voir si ya le mot END dans le buffer qui permet de déterminer la fin
        if (end_marker) {

            fwrite(buffer, 1, end_marker - buffer, file);
            printf("File transmission completed.\n");
            break;
        }

        fwrite(buffer, 1, n, file);
        bzero(buffer, BUFFER_SIZE);
    }

    fclose(file);

    char message[] = "File has been saved";
    send(client_socket, message, sizeof(message), 0);
}


/**
 * @brief Envoie la data d'un fichier demandé par l'utilisateur via /get (ne marche que pour les fichiers sauvergarder par le serveur qui se termine donc par .saved)
 */
void send_file(int client_socket, char* filename) {
    char buffer[BUFFER_SIZE];
    char error[] = "Sorry, the file that you request isn't available";

    strcat(filename, ".saved");  // Ajouter l'extension .saved
    FILE *file = fopen(filename, "rb");
    if (!file) {
        send(client_socket, error, strlen(error), 0);
        return;
    } else {
        printf("[+] Sending the file to remote client\n");
    }

    ssize_t n;
    while ((n = fread(buffer, 1, BUFFER_SIZE, file)) > 0) {
        if (send(client_socket, buffer, n, 0) == -1) {
            perror("[-] Error sending data to client");
            fclose(file);
            return;
        }
    }

    fclose(file);

     strcpy(buffer, "END");
    send(client_socket, buffer, strlen(buffer), 0);
}

/**
 * @brief Met à jour le statut d'un client
 * @param client_socket Socket du client
 * @param status Nouveau statut
 */
void update_client_status(int client_socket, const char *status) {
    char username[USERNAME_LENGTH] = "";
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
 * @brief Thread gérant un client connecté
 * @param arg Pointeur vers le socket du client
 * @return NULL
 */
void *handle_client(void *arg) {
    int client_socket = *(int*)arg;
    free(arg);
    char buffer[BUFFER_SIZE];
    char username[USERNAME_LENGTH];
    char password[PASSWORD_LENGTH];
    int auth_attempts = 0;
    const int MAX_AUTH_ATTEMPTS = 3;

    // Authentification
    while (auth_attempts < MAX_AUTH_ATTEMPTS) {
        // Recevoir le nom d'utilisateur
        memset(buffer, 0, BUFFER_SIZE);
        if (recv(client_socket, buffer, BUFFER_SIZE - 1, 0) <= 0) {
            close(client_socket);
            return NULL;
        }
        strncpy(username, buffer, USERNAME_LENGTH - 1);

        // Vérifier si l'utilisateur existe
        if (!user_exists(username)) {
            const char *error_msg = "User does not exist!\n";
            send(client_socket, error_msg, strlen(error_msg), 0);
            close(client_socket);
            return NULL;
        }

        // Demander le mot de passe
        const char *prompt = "Enter password: ";
        send(client_socket, prompt, strlen(prompt), 0);

        // Recevoir le mot de passe
        memset(buffer, 0, BUFFER_SIZE);
        if (recv(client_socket, buffer, BUFFER_SIZE - 1, 0) <= 0) {
            close(client_socket);
            return NULL;
        }
        strncpy(password, buffer, PASSWORD_LENGTH - 1);

        // Vérifier l'authentification
        if (authenticate_user(username, password)) {
            const char *success_msg = "Authentication successful!\n";
            fflush(stdout);
            send(client_socket, success_msg, strlen(success_msg), 0);
            break;
        } else {
            auth_attempts++;
            if (auth_attempts < MAX_AUTH_ATTEMPTS) {
                char error_msg[100];
                snprintf(error_msg, sizeof(error_msg),
                    "Wrong password. %d attempts remaining.\n",
                    MAX_AUTH_ATTEMPTS - auth_attempts);
                send(client_socket, error_msg, strlen(error_msg), 0);
            } else {
                const char *final_msg = "Too many failed attempts. Connection closed.\n";
                send(client_socket, final_msg, strlen(final_msg), 0);
                close(client_socket);
                return NULL;
            }
        }
    }

    // Ajouter le client authentifié
    pthread_mutex_lock(&clients_mutex);
    int client_index = client_count;
    strncpy(clients[client_index].username, username, USERNAME_LENGTH - 1);
    clients[client_index].socket = client_socket;
    clients[client_index].is_admin = (strcmp(username, "Admin") == 0);
    clients[client_index].is_authenticated = 1;
    clients[client_index].status[0] = '\0';
    client_count++;
    update_max_clients();
    pthread_mutex_unlock(&clients_mutex);

    // Envoyer message de bienvenue
    char welcome_msg[BUFFER_SIZE];
    snprintf(welcome_msg, BUFFER_SIZE, "Welcome %s%s!\n",
             username, clients[client_index].is_admin ? " (admin)" : "");
    send(client_socket, welcome_msg, strlen(welcome_msg), 0);

    // Annoncer la connexion aux autres
    char join_msg[BUFFER_SIZE];
    snprintf(join_msg, BUFFER_SIZE, "# %s%s has joined the chat\n",
             username, clients[client_index].is_admin ? " (*)" : "");
    broadcast_message(join_msg, client_socket);
    log_message(join_msg);

    while (1) {
        memset(buffer, 0, BUFFER_SIZE);
        int bytes_read = recv(client_socket, buffer, BUFFER_SIZE - 1, 0);
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
        } else if (strncmp(buffer, "/push ", 6) == 0){
            char * filename = buffer + 6;
            receive_file(client_socket, filename);
        } else if (strncmp(buffer, "/get ", 5) == 0){
          char * filename = buffer + 5;
          send_file(client_socket, filename);
        } else {
            broadcast_message(buffer, client_socket);
        }
    }

    remove_client(client_socket);
    close(client_socket);
    return NULL;
}

/**
 * @brief Fonction principale
 * @param argc Nombre d'arguments
 * @param argv Tableau des arguments
 * @return 0 si succès, 1 si erreur
 */
int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <port>\n", argv[0]);
        return 1;
    }

    // Charger les utilisateurs depuis le fichier de configuration
    if (!load_users()) {
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
