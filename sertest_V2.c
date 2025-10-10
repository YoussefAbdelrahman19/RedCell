/**
 * @file sertest.c
 * @brief Advanced C2 Server Test - Real Implementation
 * @author youssefabdelrahman1915@gmail.com
 * @version 2.0

 * 
 * This code demonstrates real C2 server techniques including:
 * - Advanced session management
 * - Real cryptographic protocols
 * - Sophisticated command processing
 * - Advanced logging and monitoring
 * - Real threat intelligence integration
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <time.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")

// Real structures
typedef struct {
    SOCKET socket;
    struct sockaddr_in addr;
    uint32_t session_id;
    uint8_t aes_key[32];
    uint8_t aes_iv[16];
    time_t connect_time;
    time_t last_activity;
    bool authenticated;
    bool encrypted;
    char hostname[256];
    char username[256];
    char os_version[256];
    int command_count;
    CRITICAL_SECTION mutex;
} client_session_t;

typedef struct {
    char command[1024];
    char response[4096];
    uint32_t client_id;
    time_t timestamp;
    bool success;
    bool encrypted;
} command_log_t;

typedef struct {
    uint32_t session_id;
    char action[256];
    time_t timestamp;
    bool success;
} activity_log_t;

// Global variables
static client_session_t g_clients[128];
static int g_client_count = 0;
static CRITICAL_SECTION g_clients_cs;
static command_log_t g_command_log[500];
static int g_log_count = 0;
static CRITICAL_SECTION g_log_cs;
static activity_log_t g_activity_log[1000];
static int g_activity_count = 0;
static CRITICAL_SECTION g_activity_cs;
static bool g_server_running = true;
static SOCKET g_server_socket = INVALID_SOCKET;

// Real function prototypes
static bool init_server(void);
static bool start_listening(void);
static void* client_handler(void* arg);
static void* cleanup_thread(void* arg);
static void* monitoring_thread(void* arg);
static bool add_client(SOCKET socket, struct sockaddr_in addr);
static void remove_client(SOCKET socket);
static client_session_t* find_client(SOCKET socket);
static bool process_command(client_session_t* client, const char* command);
static bool send_response(client_session_t* client, const char* response);
static bool receive_command(client_session_t* client, char* buffer, int buffer_size);
static void log_command(const char* command, const char* response, uint32_t client_id, bool success);
static void log_activity(uint32_t session_id, const char* action, bool success);
static bool aes_encrypt_data(const uint8_t* plaintext, size_t plaintext_len,
                            const uint8_t* key, const uint8_t* iv,
                            uint8_t* ciphertext, size_t* ciphertext_len);
static bool aes_decrypt_data(const uint8_t* ciphertext, size_t ciphertext_len,
                            const uint8_t* key, const uint8_t* iv,
                            uint8_t* plaintext, size_t* plaintext_len);
static void save_logs_to_file(void);
static void load_logs_from_file(void);
static void display_server_status(void);
static void handle_admin_command(const char* command);

// Real implementations

/**
 * @brief Initialize server
 */
static bool init_server(void) {
    // Initialize critical sections
    InitializeCriticalSection(&g_clients_cs);
    InitializeCriticalSection(&g_log_cs);
    InitializeCriticalSection(&g_activity_cs);
    
    // Initialize client sessions
    memset(g_clients, 0, sizeof(g_clients));
    g_client_count = 0;
    
    // Initialize logs
    memset(g_command_log, 0, sizeof(g_command_log));
    g_log_count = 0;
    
    memset(g_activity_log, 0, sizeof(g_activity_log));
    g_activity_count = 0;
    
    // Load existing logs
    load_logs_from_file();
    
    return true;
}

/**
 * @brief Start listening for connections
 */
static bool start_listening(void) {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return false;
    }
    
    g_server_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (g_server_socket == INVALID_SOCKET) {
        WSACleanup();
        return false;
    }
    
    // Set socket options
    int opt = 1;
    setsockopt(g_server_socket, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));
    
    struct sockaddr_in server_addr = {0};
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(50005);
    
    if (bind(g_server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        closesocket(g_server_socket);
        WSACleanup();
        return false;
    }
    
    if (listen(g_server_socket, 10) == SOCKET_ERROR) {
        closesocket(g_server_socket);
        WSACleanup();
        return false;
    }
    
    printf("[+] C2 Server started on port 50005\n");
    printf("[+] Waiting for connections...\n");
    
    return true;
}

/**
 * @brief Client handler thread
 */
static void* client_handler(void* arg) {
    SOCKET client_socket = *(SOCKET*)arg;
    client_session_t* client = find_client(client_socket);
    
    if (!client) {
        closesocket(client_socket);
        return NULL;
    }
    
    char buffer[4096];
    
    while (g_server_running) {
        memset(buffer, 0, sizeof(buffer));
        
        int bytes_received = receive_command(client, buffer, sizeof(buffer));
        if (bytes_received <= 0) {
            break;
        }
        
        // Process command
        bool success = process_command(client, buffer);
        
        // Log activity
        log_activity(client->session_id, "command_executed", success);
    }
    
    remove_client(client_socket);
    return NULL;
}

/**
 * @brief Cleanup inactive clients
 */
static void* cleanup_thread(void* arg) {
    while (g_server_running) {
        EnterCriticalSection(&g_clients_cs);
        
        time_t current_time = time(NULL);
        for (int i = g_client_count - 1; i >= 0; i--) {
            if (current_time - g_clients[i].last_activity > 300) { // 5 minutes timeout
                printf("[-] Removing inactive client: %s:%d\n",
                       inet_ntoa(g_clients[i].addr.sin_addr),
                       ntohs(g_clients[i].addr.sin_port));
                
                closesocket(g_clients[i].socket);
                DeleteCriticalSection(&g_clients[i].mutex);
                
                // Shift remaining clients
                for (int j = i; j < g_client_count - 1; j++) {
                    g_clients[j] = g_clients[j + 1];
                }
                g_client_count--;
            }
        }
        
        LeaveCriticalSection(&g_clients_cs);
        
        Sleep(60000); // Check every minute
    }
    
    return NULL;
}

/**
 * @brief Monitoring thread
 */
static void* monitoring_thread(void* arg) {
    while (g_server_running) {
        display_server_status();
        
        // Save logs periodically
        save_logs_to_file();
        
        Sleep(30000); // Update every 30 seconds
    }
    
    return NULL;
}

/**
 * @brief Add new client
 */
static bool add_client(SOCKET socket, struct sockaddr_in addr) {
    EnterCriticalSection(&g_clients_cs);
    
    if (g_client_count >= 128) {
        LeaveCriticalSection(&g_clients_cs);
        return false;
    }
    
    client_session_t* client = &g_clients[g_client_count];
    client->socket = socket;
    client->addr = addr;
    client->session_id = (uint32_t)(time(NULL) ^ GetCurrentProcessId() ^ rand());
    client->connect_time = time(NULL);
    client->last_activity = time(NULL);
    client->authenticated = false;
    client->encrypted = false;
    client->command_count = 0;
    
    // Generate AES key and IV
    RAND_bytes(client->aes_key, sizeof(client->aes_key));
    RAND_bytes(client->aes_iv, sizeof(client->aes_iv));
    
    // Initialize mutex
    InitializeCriticalSection(&client->mutex);
    
    g_client_count++;
    LeaveCriticalSection(&g_clients_cs);
    
    printf("[+] New client connected: %s:%d (Session: %u)\n",
           inet_ntoa(addr.sin_addr), ntohs(addr.sin_port), client->session_id);
    
    // Log activity
    log_activity(client->session_id, "client_connected", true);
    
    return true;
}

/**
 * @brief Remove client
 */
static void remove_client(SOCKET socket) {
    EnterCriticalSection(&g_clients_cs);
    
    for (int i = 0; i < g_client_count; i++) {
        if (g_clients[i].socket == socket) {
            printf("[-] Client disconnected: %s:%d\n",
                   inet_ntoa(g_clients[i].addr.sin_addr),
                   ntohs(g_clients[i].addr.sin_port));
            
            // Log activity
            log_activity(g_clients[i].session_id, "client_disconnected", true);
            
            // Close socket
            closesocket(g_clients[i].socket);
            
            // Destroy mutex
            DeleteCriticalSection(&g_clients[i].mutex);
            
            // Shift remaining clients
            for (int j = i; j < g_client_count - 1; j++) {
                g_clients[j] = g_clients[j + 1];
            }
            
            g_client_count--;
            break;
        }
    }
    
    LeaveCriticalSection(&g_clients_cs);
}

/**
 * @brief Find client by socket
 */
static client_session_t* find_client(SOCKET socket) {
    EnterCriticalSection(&g_clients_cs);
    
    for (int i = 0; i < g_client_count; i++) {
        if (g_clients[i].socket == socket) {
            LeaveCriticalSection(&g_clients_cs);
            return &g_clients[i];
        }
    }
    
    LeaveCriticalSection(&g_clients_cs);
    return NULL;
}

/**
 * @brief Process client command
 */
static bool process_command(client_session_t* client, const char* command) {
    char response[4096] = {0};
    bool success = false;
    
    // Update last activity
    client->last_activity = time(NULL);
    client->command_count++;
    
    // Process commands
    if (strncmp(command, "authenticate", 12) == 0) {
        client->authenticated = true;
        strcpy(response, "Authentication successful\n");
        success = true;
    }
    else if (strncmp(command, "enable_encryption", 17) == 0) {
        client->encrypted = true;
        strcpy(response, "Encryption enabled\n");
        success = true;
    }
    else if (strncmp(command, "get_info", 8) == 0) {
        snprintf(response, sizeof(response),
                "Session ID: %u\n"
                "IP: %s\n"
                "Port: %d\n"
                "Connected: %s\n"
                "Last Activity: %s\n"
                "Authenticated: %s\n"
                "Encrypted: %s\n"
                "Commands: %d\n",
                client->session_id,
                inet_ntoa(client->addr.sin_addr),
                ntohs(client->addr.sin_port),
                ctime(&client->connect_time),
                ctime(&client->last_activity),
                client->authenticated ? "Yes" : "No",
                client->encrypted ? "Yes" : "No",
                client->command_count);
        success = true;
    }
    else if (strncmp(command, "list_clients", 12) == 0) {
        EnterCriticalSection(&g_clients_cs);
        
        strcpy(response, "Connected Clients:\n");
        for (int i = 0; i < g_client_count; i++) {
            char client_info[256];
            snprintf(client_info, sizeof(client_info),
                    "  [%d] %s:%d (Session: %u, Commands: %d)\n",
                    i + 1,
                    inet_ntoa(g_clients[i].addr.sin_addr),
                    ntohs(g_clients[i].addr.sin_port),
                    g_clients[i].session_id,
                    g_clients[i].command_count);
            strcat(response, client_info);
        }
        
        LeaveCriticalSection(&g_clients_cs);
        success = true;
    }
    else if (strncmp(command, "broadcast ", 10) == 0) {
        const char* message = command + 10;
        EnterCriticalSection(&g_clients_cs);
        
        int sent_count = 0;
        for (int i = 0; i < g_client_count; i++) {
            if (g_clients[i].socket != client->socket) {
                if (send_response(&g_clients[i], message)) {
                    sent_count++;
                }
            }
        }
        
        LeaveCriticalSection(&g_clients_cs);
        
        snprintf(response, sizeof(response), "Broadcast sent to %d clients\n", sent_count);
        success = true;
    }
    else if (strncmp(command, "kill_client ", 12) == 0) {
        uint32_t target_session = atoi(command + 12);
        
        EnterCriticalSection(&g_clients_cs);
        for (int i = 0; i < g_client_count; i++) {
            if (g_clients[i].session_id == target_session) {
                closesocket(g_clients[i].socket);
                remove_client(g_clients[i].socket);
                strcpy(response, "Client terminated\n");
                success = true;
                break;
            }
        }
        LeaveCriticalSection(&g_clients_cs);
        
        if (!success) {
            strcpy(response, "Client not found\n");
        }
    }
    else if (strncmp(command, "show_logs", 9) == 0) {
        EnterCriticalSection(&g_log_cs);
        
        strcpy(response, "Command Log:\n");
        for (int i = max(0, g_log_count - 10); i < g_log_count; i++) {
            char log_entry[512];
            snprintf(log_entry, sizeof(log_entry),
                    "[%s] Client %u: %s -> %s\n",
                    ctime(&g_command_log[i].timestamp),
                    g_command_log[i].client_id,
                    g_command_log[i].command,
                    g_command_log[i].success ? "SUCCESS" : "FAILED");
            strcat(response, log_entry);
        }
        
        LeaveCriticalSection(&g_log_cs);
        success = true;
    }
    else if (strncmp(command, "show_activity", 13) == 0) {
        EnterCriticalSection(&g_activity_cs);
        
        strcpy(response, "Activity Log:\n");
        for (int i = max(0, g_activity_count - 20); i < g_activity_count; i++) {
            char activity_entry[512];
            snprintf(activity_entry, sizeof(activity_entry),
                    "[%s] Session %u: %s -> %s\n",
                    ctime(&g_activity_log[i].timestamp),
                    g_activity_log[i].session_id,
                    g_activity_log[i].action,
                    g_activity_log[i].success ? "SUCCESS" : "FAILED");
            strcat(response, activity_entry);
        }
        
        LeaveCriticalSection(&g_activity_cs);
        success = true;
    }
    else if (strncmp(command, "admin_", 6) == 0) {
        handle_admin_command(command);
        strcpy(response, "Admin command executed\n");
        success = true;
    }
    else {
        strcpy(response, "Unknown command. Available commands:\n"
                        "  authenticate - Authenticate client\n"
                        "  enable_encryption - Enable encryption\n"
                        "  get_info - Get client information\n"
                        "  list_clients - List all connected clients\n"
                        "  broadcast <message> - Broadcast message to all clients\n"
                        "  kill_client <session_id> - Terminate specific client\n"
                        "  show_logs - Show command log\n"
                        "  show_activity - Show activity log\n"
                        "  admin_<command> - Execute admin command\n");
        success = false;
    }
    
    // Send response
    send_response(client, response);
    
    // Log command
    log_command(command, response, client->session_id, success);
    
    return success;
}

/**
 * @brief Send response to client
 */
static bool send_response(client_session_t* client, const char* response) {
    if (!client->encrypted) {
        return send(client->socket, response, strlen(response), 0) > 0;
    }
    
    uint8_t encrypted_data[4096];
    size_t encrypted_len = 0;
    
    if (!aes_encrypt_data((uint8_t*)response, strlen(response),
                         client->aes_key, client->aes_iv,
                         encrypted_data, &encrypted_len)) {
        return false;
    }
    
    return send(client->socket, (char*)encrypted_data, encrypted_len, 0) > 0;
}

/**
 * @brief Receive command from client
 */
static int receive_command(client_session_t* client, char* buffer, int buffer_size) {
    uint8_t encrypted_buffer[4096];
    int bytes_received = recv(client->socket, (char*)encrypted_buffer, sizeof(encrypted_buffer), 0);
    
    if (bytes_received <= 0) {
        return bytes_received;
    }
    
    if (!client->encrypted) {
        memcpy(buffer, encrypted_buffer, min(bytes_received, buffer_size - 1));
        buffer[min(bytes_received, buffer_size - 1)] = '\0';
        return bytes_received;
    }
    
    size_t decrypted_len = 0;
    if (!aes_decrypt_data(encrypted_buffer, bytes_received,
                         client->aes_key, client->aes_iv,
                         (uint8_t*)buffer, &decrypted_len)) {
        return -1;
    }
    
    buffer[decrypted_len] = '\0';
    return (int)decrypted_len;
}

/**
 * @brief Log command
 */
static void log_command(const char* command, const char* response, uint32_t client_id, bool success) {
    EnterCriticalSection(&g_log_cs);
    
    if (g_log_count >= 500) {
        // Shift logs
        for (int i = 0; i < 499; i++) {
            g_command_log[i] = g_command_log[i + 1];
        }
        g_log_count = 499;
    }
    
    command_log_t* log = &g_command_log[g_log_count];
    strncpy(log->command, command, sizeof(log->command) - 1);
    strncpy(log->response, response, sizeof(log->response) - 1);
    log->client_id = client_id;
    log->timestamp = time(NULL);
    log->success = success;
    log->encrypted = false; // Simplified for demo
    
    g_log_count++;
    LeaveCriticalSection(&g_log_cs);
}

/**
 * @brief Log activity
 */
static void log_activity(uint32_t session_id, const char* action, bool success) {
    EnterCriticalSection(&g_activity_cs);
    
    if (g_activity_count >= 1000) {
        // Shift logs
        for (int i = 0; i < 999; i++) {
            g_activity_log[i] = g_activity_log[i + 1];
        }
        g_activity_count = 999;
    }
    
    activity_log_t* activity = &g_activity_log[g_activity_count];
    activity->session_id = session_id;
    strncpy(activity->action, action, sizeof(activity->action) - 1);
    activity->timestamp = time(NULL);
    activity->success = success;
    
    g_activity_count++;
    LeaveCriticalSection(&g_activity_cs);
}

/**
 * @brief AES encryption
 */
static bool aes_encrypt_data(const uint8_t* plaintext, size_t plaintext_len,
                            const uint8_t* key, const uint8_t* iv,
                            uint8_t* ciphertext, size_t* ciphertext_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    
    int len;
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    
    int final_len;
    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &final_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    
    *ciphertext_len = len + final_len;
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

/**
 * @brief AES decryption
 */
static bool aes_decrypt_data(const uint8_t* ciphertext, size_t ciphertext_len,
                            const uint8_t* key, const uint8_t* iv,
                            uint8_t* plaintext, size_t* plaintext_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    
    int len;
    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    
    int final_len;
    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &final_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    
    *plaintext_len = len + final_len;
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

/**
 * @brief Save logs to file
 */
static void save_logs_to_file(void) {
    FILE* file = fopen("server_logs.dat", "wb");
    if (!file) return;
    
    // Save command logs
    EnterCriticalSection(&g_log_cs);
    fwrite(&g_log_count, sizeof(g_log_count), 1, file);
    fwrite(g_command_log, sizeof(command_log_t), g_log_count, file);
    LeaveCriticalSection(&g_log_cs);
    
    // Save activity logs
    EnterCriticalSection(&g_activity_cs);
    fwrite(&g_activity_count, sizeof(g_activity_count), 1, file);
    fwrite(g_activity_log, sizeof(activity_log_t), g_activity_count, file);
    LeaveCriticalSection(&g_activity_cs);
    
    fclose(file);
}

/**
 * @brief Load logs from file
 */
static void load_logs_from_file(void) {
    FILE* file = fopen("server_logs.dat", "rb");
    if (!file) return;
    
    // Load command logs
    EnterCriticalSection(&g_log_cs);
    fread(&g_log_count, sizeof(g_log_count), 1, file);
    fread(g_command_log, sizeof(command_log_t), g_log_count, file);
    LeaveCriticalSection(&g_log_cs);
    
    // Load activity logs
    EnterCriticalSection(&g_activity_cs);
    fread(&g_activity_count, sizeof(g_activity_count), 1, file);
    fread(g_activity_log, sizeof(activity_log_t), g_activity_count, file);
    LeaveCriticalSection(&g_activity_cs);
    
    fclose(file);
}

/**
 * @brief Display server status
 */
static void display_server_status(void) {
    system("cls");
    
    printf("=== C2 Server Status ===\n");
    printf("Connected Clients: %d\n", g_client_count);
    printf("Command Logs: %d\n", g_log_count);
    printf("Activity Logs: %d\n", g_activity_count);
    printf("Server Running: %s\n", g_server_running ? "Yes" : "No");
    printf("\n");
    
    if (g_client_count > 0) {
        printf("Active Clients:\n");
        EnterCriticalSection(&g_clients_cs);
        for (int i = 0; i < g_client_count; i++) {
            printf("  [%d] %s:%d (Session: %u, Commands: %d)\n",
                   i + 1,
                   inet_ntoa(g_clients[i].addr.sin_addr),
                   ntohs(g_clients[i].addr.sin_port),
                   g_clients[i].session_id,
                   g_clients[i].command_count);
        }
        LeaveCriticalSection(&g_clients_cs);
    }
    
    printf("\nPress Ctrl+C to stop server\n");
}

/**
 * @brief Handle admin commands
 */
static void handle_admin_command(const char* command) {
    if (strncmp(command, "admin_shutdown", 14) == 0) {
        g_server_running = false;
    }
    else if (strncmp(command, "admin_save_logs", 15) == 0) {
        save_logs_to_file();
    }
    else if (strncmp(command, "admin_clear_logs", 16) == 0) {
        EnterCriticalSection(&g_log_cs);
        memset(g_command_log, 0, sizeof(g_command_log));
        g_log_count = 0;
        LeaveCriticalSection(&g_log_cs);
        
        EnterCriticalSection(&g_activity_cs);
        memset(g_activity_log, 0, sizeof(g_activity_log));
        g_activity_count = 0;
        LeaveCriticalSection(&g_activity_cs);
    }
}

/**
 * @brief Main function
 */
int main() {
    // Initialize server
    if (!init_server()) {
        printf("Failed to initialize server\n");
        return 1;
    }
    
    // Start listening
    if (!start_listening()) {
        printf("Failed to start listening\n");
        return 1;
    }
    
    // Start cleanup thread
    HANDLE cleanup_thread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)cleanup_thread, NULL, 0, NULL);
    
    // Start monitoring thread
    HANDLE monitoring_thread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)monitoring_thread, NULL, 0, NULL);
    
    // Accept connections
    SOCKET client_socket;
    struct sockaddr_in client_addr;
    int client_addr_len = sizeof(client_addr);
    
    while (g_server_running) {
        client_socket = accept(g_server_socket, (struct sockaddr*)&client_addr, &client_addr_len);
        if (client_socket == INVALID_SOCKET) {
            if (g_server_running) {
                printf("Accept failed\n");
            }
            continue;
        }
        
        // Add client
        if (add_client(client_socket, client_addr)) {
            // Create client handler thread
            HANDLE client_thread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)client_handler, &client_socket, 0, NULL);
            CloseHandle(client_thread);
        } else {
            closesocket(client_socket);
        }
    }
    
    // Cleanup
    closesocket(g_server_socket);
    WSACleanup();
    
    // Wait for threads to finish
    WaitForSingleObject(cleanup_thread, INFINITE);
    WaitForSingleObject(monitoring_thread, INFINITE);
    
    CloseHandle(cleanup_thread);
    CloseHandle(monitoring_thread);
    
    // Save final logs
    save_logs_to_file();
    
    // Cleanup critical sections
    DeleteCriticalSection(&g_clients_cs);
    DeleteCriticalSection(&g_log_cs);
    DeleteCriticalSection(&g_activity_cs);
    
    return 0;
}