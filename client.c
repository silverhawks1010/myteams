/**
 * @file client.c
 * @brief Client de chat avec authentification
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>


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

/** Variables globales */
int client_socket;                          /**< Socket du client */
bool pause_mode = false;                    /**< Mode "Ne pas déranger" */
char current_status[STATUS_LENGTH] = "";    /**< Statut actuel de l'utilisateur */

/**
 * @brief Affiche les informations d'aide sur les commandes disponibles
 */
void print_help() {
    printf("\nAvailable commands:\n");
    printf("/help - Display this help message\n");
    printf("/quit - Exit the chat\n");
    printf("/status <message> - Update your status\n");
    printf("/pause - Toggle Do Not Disturb mode\n");
    printf("/info - Display server information\n");
    printf("/kick <username> - Kick a user (admin only)\n");
}

/**
 * @brief Envoyer un fichier au serveur
 */
void send_file(int socket, const char *filename) {
    char buffer[BUFFER_SIZE];
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("Error while opening the file");
        return;
    } else {
        printf("[+] Sending the file to remote server\n");
    }

    ssize_t n;
    while ((n = fread(buffer, 1, BUFFER_SIZE, file)) > 0) {
        if (send(socket, buffer, n, 0) == -1) {
            perror("[-] Error sending data to server");
            fclose(file);
            return;
        }
        bzero(buffer, BUFFER_SIZE);  // Nettoyer le buffer après l'envoi
    }

    fclose(file);

    strcpy(buffer, "END");
    send(socket, buffer, strlen(buffer) + 1, 0);
}

/**
 * @brief Pour recevoir un fichier demandé via /get
 */
void receive_file(int socket, const char *filename) {
    char buffer[BUFFER_SIZE];
    FILE *file = fopen(filename, "wb");
    if (!file) {
        perror("Error while creating the file");
        return;
    }

    while (1) {
        ssize_t n = recv(socket, buffer, BUFFER_SIZE, 0);
        if (n <= 0) {
            if (n == 0) {
                printf("Connexion close by the server\n");
            } else {
                perror("Error during reception\n");
            }
            break;
        }

        // Vérifier si le serveur a envoyé un message d'erreur
        if (strncmp(buffer, "Sorry, the file that you request isn't available", 47) == 0) {
            printf("[-] The requested file is not available\n");
            fclose(file);
            remove(filename);  // Supprime le fichier vide créé
            return;
        }

        if (n == 3 && strncmp(buffer, "END", 3) == 0) {
            printf("[+] File transmission completed.\n");
            break;
        }

        fwrite(buffer, 1, n, file);
    }

    fclose(file);
}

/**
 * @brief Gestionnaire du signal SIGINT (Ctrl+C)
 * @param sig Numéro du signal
 */
void handle_sigint(int sig) {
    (void)sig;
    printf("\nDeconnexion...\n");
    close(client_socket);
    exit(0);
}

/**
 * @brief Thread de réception des messages
 * @param arg Pointeur vers le socket client
 * @return NULL
 */
void *receive_handler(void *arg) {
    int sock = *(int*)arg;
    char buffer[BUFFER_SIZE];
    ssize_t bytes_received;

    while ((bytes_received = recv(sock, buffer, BUFFER_SIZE - 1, 0)) > 0) {
        buffer[bytes_received] = '\0';
        if (!pause_mode) {
            printf("%s", buffer);
            fflush(stdout);
        }
    }

    printf("Disconnected.\n");
    close(sock);
    exit(0);
    return NULL;
}

/**
 * @brief Fonction principale
 * @param argc Nombre d'arguments
 * @param argv Tableau des arguments
 * @return 0 si succès, 1 si erreur
 */
int main(int argc, char *argv[]) {
    if (argc != 4) {
        printf("Usage: %s <server_ip> <port> <username>\n", argv[0]);
        return 1;
    }

    const char *server_ip = argv[1];
    int port = atoi(argv[2]);
    const char *username = argv[3];

    client_socket = socket(AF_INET, SOCK_STREAM, 0);
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

    // Envoyer le nom d'utilisateur
    write(client_socket, username, strlen(username));

    // Lire la réponse du serveur
    char buffer[BUFFER_SIZE];
    ssize_t bytes_read = read(client_socket, buffer, BUFFER_SIZE - 1);
    if (bytes_read <= 0) {
        printf("Server disconnected\n");
        close(client_socket);
        return 1;
    }
    buffer[bytes_read] = '\0';
    printf("%s", buffer);

    // Si l'utilisateur n'existe pas, quitter
    if (strstr(buffer, "does not exist")) {
        close(client_socket);
        return 1;
    }

    // Boucle d'authentification
    while (1) {
        // Lire le mot de passe
        char password[BUFFER_SIZE];
        if (fgets(password, BUFFER_SIZE, stdin) == NULL) {
            printf("Error reading password\n");
            close(client_socket);
            return 1;
        }
        password[strcspn(password, "\n")] = 0;

        // Envoyer le mot de passe
        write(client_socket, password, strlen(password));

        // Lire la reponse d'authentification
        bytes_read = read(client_socket, buffer, BUFFER_SIZE - 1);
        if (bytes_read <= 0) {
            printf("Server disconnected\n");
            close(client_socket);
            return 1;
        }
        buffer[bytes_read] = '\0';
        printf("%s", buffer);

        // Si authentification réussie, sortir de la boucle
        if (strstr(buffer, "successful")) {
            break;
        }

        // Si trop de tentatives ou mot de passe incorrect, quitter
        if (strstr(buffer, "Too many") || strstr(buffer, "Wrong password")) {
            close(client_socket);
            printf("Authentication failed. Exiting...\n");
            return 1;
        }
    }

    // Créer le thread de récéption
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
        } else if (strcmp(message, "/quit") == 0) {
            close(client_socket);
            pthread_cancel(recv_thread);
            pthread_join(recv_thread, NULL);
            return 0;
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
        } else if (strncmp(message, "/push ", 6) == 0) {
            write(client_socket, message, strlen(message));
            char filename[1024];
            if (sscanf(message + 6, "%255s", filename) == 1) {
                send_file(client_socket, filename);
                continue;
                } else {
                printf("Error : no file specified\n");
                continue;
                }
        } else if ((strncmp(message, "/get ", 5) == 0)){
            char* filename = message + 5;
            printf("%s\n", filename);
            write(client_socket, message, strlen(message));
            receive_file(client_socket, filename);
            continue;
        }

        if (!pause_mode) {
            // Show message locally with admin star if first client
            if (current_status[0] != '\0') {
                printf("# %s (me) (%s) > %s\n",
                    username,
                    current_status,
                    message);
            } else {
                printf("# %s (me) > %s\n",
                    username,
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
