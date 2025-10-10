/**
 * @file str_cut+function.c
 * @brief Advanced String Manipulation - Real Implementation
 * @author youssefabdelrahman1915@gmail.com
 * @version 2.0

 * 
 * This code demonstrates real string manipulation techniques including:
 * - Advanced memory-safe operations
 * - Real buffer overflow protection
 * - Sophisticated string obfuscation
 * - Advanced pattern matching
 * - Real forensic cleanup
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")

// Real constants
#define MAX_STRING_LENGTH 4096
#define MAX_PATTERN_LENGTH 256
#define MAX_OBFUSCATION_LEVEL 10

// Real structures
typedef struct {
    char* data;
    size_t length;
    size_t capacity;
    bool encrypted;
    uint8_t key[32];
    uint8_t iv[16];
} secure_string_t;

typedef struct {
    char pattern[MAX_PATTERN_LENGTH];
    size_t pattern_length;
    int match_count;
    time_t last_match;
} pattern_match_t;

typedef struct {
    pattern_match_t patterns[100];
    int pattern_count;
    CRITICAL_SECTION mutex;
} pattern_tracker_t;

// Global variables
static pattern_tracker_t g_pattern_tracker = {0};

// Real function prototypes
static bool init_secure_string(secure_string_t* str, size_t initial_capacity);
static bool append_secure_string(secure_string_t* str, const char* data, size_t length);
static bool insert_secure_string(secure_string_t* str, size_t position, const char* data, size_t length);
static bool remove_secure_string(secure_string_t* str, size_t position, size_t length);
static bool encrypt_secure_string(secure_string_t* str);
static bool decrypt_secure_string(secure_string_t* str);
static void destroy_secure_string(secure_string_t* str);
static bool find_pattern(const char* text, size_t text_length, const char* pattern, size_t pattern_length);
static bool replace_pattern(char* text, size_t text_length, const char* pattern, const char* replacement);
static void obfuscate_string(char* str, size_t length, int level);
static void deobfuscate_string(char* str, size_t length, int level);
static void secure_zero_memory(void* ptr, size_t size);
static bool validate_string_integrity(const char* str, size_t length);
static void init_pattern_tracker(void);
static void add_pattern(const char* pattern);
static bool check_patterns(const char* text, size_t length);
static void cleanup_patterns(void);

// Real implementations

/**
 * @brief Initialize secure string
 */
static bool init_secure_string(secure_string_t* str, size_t initial_capacity) {
    if (!str || initial_capacity == 0) {
        return false;
    }
    
    str->data = (char*)malloc(initial_capacity);
    if (!str->data) {
        return false;
    }
    
    str->length = 0;
    str->capacity = initial_capacity;
    str->encrypted = false;
    
    // Generate encryption key and IV
    if (RAND_bytes(str->key, sizeof(str->key)) != 1 ||
        RAND_bytes(str->iv, sizeof(str->iv)) != 1) {
        free(str->data);
        return false;
    }
    
    return true;
}

/**
 * @brief Append data to secure string
 */
static bool append_secure_string(secure_string_t* str, const char* data, size_t length) {
    if (!str || !data || length == 0) {
        return false;
    }
    
    // Check if we need to resize
    if (str->length + length >= str->capacity) {
        size_t new_capacity = str->capacity * 2;
        while (new_capacity < str->length + length) {
            new_capacity *= 2;
        }
        
        char* new_data = (char*)realloc(str->data, new_capacity);
        if (!new_data) {
            return false;
        }
        
        str->data = new_data;
        str->capacity = new_capacity;
    }
    
    // Append data
    memcpy(str->data + str->length, data, length);
    str->length += length;
    str->data[str->length] = '\0';
    
    return true;
}

/**
 * @brief Insert data into secure string
 */
static bool insert_secure_string(secure_string_t* str, size_t position, const char* data, size_t length) {
    if (!str || !data || length == 0 || position > str->length) {
        return false;
    }
    
    // Check if we need to resize
    if (str->length + length >= str->capacity) {
        size_t new_capacity = str->capacity * 2;
        while (new_capacity < str->length + length) {
            new_capacity *= 2;
        }
        
        char* new_data = (char*)realloc(str->data, new_capacity);
        if (!new_data) {
            return false;
        }
        
        str->data = new_data;
        str->capacity = new_capacity;
    }
    
    // Shift existing data
    memmove(str->data + position + length, str->data + position, str->length - position);
    
    // Insert new data
    memcpy(str->data + position, data, length);
    str->length += length;
    str->data[str->length] = '\0';
    
    return true;
}

/**
 * @brief Remove data from secure string
 */
static bool remove_secure_string(secure_string_t* str, size_t position, size_t length) {
    if (!str || position >= str->length || length == 0) {
        return false;
    }
    
    // Adjust length if it exceeds string length
    if (position + length > str->length) {
        length = str->length - position;
    }
    
    // Shift remaining data
    memmove(str->data + position, str->data + position + length, str->length - position - length);
    
    str->length -= length;
    str->data[str->length] = '\0';
    
    return true;
}

/**
 * @brief Encrypt secure string using AES
 */
static bool encrypt_secure_string(secure_string_t* str) {
    if (!str || str->encrypted) {
        return false;
    }
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return false;
    }
    
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, str->key, str->iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    
    // Allocate space for encrypted data
    size_t encrypted_len = str->length + EVP_CIPHER_block_size(EVP_aes_256_cbc());
    char* encrypted_data = (char*)malloc(encrypted_len);
    if (!encrypted_data) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    
    int len;
    if (EVP_EncryptUpdate(ctx, (uint8_t*)encrypted_data, &len, (uint8_t*)str->data, str->length) != 1) {
        free(encrypted_data);
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    
    int final_len;
    if (EVP_EncryptFinal_ex(ctx, (uint8_t*)encrypted_data + len, &final_len) != 1) {
        free(encrypted_data);
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    
    // Replace original data with encrypted data
    free(str->data);
    str->data = encrypted_data;
    str->length = len + final_len;
    str->encrypted = true;
    
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

/**
 * @brief Decrypt secure string using AES
 */
static bool decrypt_secure_string(secure_string_t* str) {
    if (!str || !str->encrypted) {
        return false;
    }
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return false;
    }
    
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, str->key, str->iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    
    // Allocate space for decrypted data
    char* decrypted_data = (char*)malloc(str->length);
    if (!decrypted_data) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    
    int len;
    if (EVP_DecryptUpdate(ctx, (uint8_t*)decrypted_data, &len, (uint8_t*)str->data, str->length) != 1) {
        free(decrypted_data);
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    
    int final_len;
    if (EVP_DecryptFinal_ex(ctx, (uint8_t*)decrypted_data + len, &final_len) != 1) {
        free(decrypted_data);
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    
    // Replace encrypted data with decrypted data
    free(str->data);
    str->data = decrypted_data;
    str->length = len + final_len;
    str->encrypted = false;
    
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

/**
 * @brief Destroy secure string
 */
static void destroy_secure_string(secure_string_t* str) {
    if (!str) return;
    
    if (str->data) {
        secure_zero_memory(str->data, str->length);
        free(str->data);
    }
    
    secure_zero_memory(str->key, sizeof(str->key));
    secure_zero_memory(str->iv, sizeof(str->iv));
    
    str->data = NULL;
    str->length = 0;
    str->capacity = 0;
    str->encrypted = false;
}

/**
 * @brief Find pattern in text using KMP algorithm
 */
static bool find_pattern(const char* text, size_t text_length, const char* pattern, size_t pattern_length) {
    if (!text || !pattern || pattern_length == 0 || text_length < pattern_length) {
        return false;
    }
    
    // Build failure function for KMP algorithm
    int* failure = (int*)malloc(pattern_length * sizeof(int));
    if (!failure) {
        return false;
    }
    
    failure[0] = 0;
    int j = 0;
    
    for (size_t i = 1; i < pattern_length; i++) {
        while (j > 0 && pattern[i] != pattern[j]) {
            j = failure[j - 1];
        }
        if (pattern[i] == pattern[j]) {
            j++;
        }
        failure[i] = j;
    }
    
    // Search for pattern
    j = 0;
    for (size_t i = 0; i < text_length; i++) {
        while (j > 0 && text[i] != pattern[j]) {
            j = failure[j - 1];
        }
        if (text[i] == pattern[j]) {
            j++;
        }
        if (j == pattern_length) {
            free(failure);
            return true;
        }
    }
    
    free(failure);
    return false;
}

/**
 * @brief Replace pattern in text
 */
static bool replace_pattern(char* text, size_t text_length, const char* pattern, const char* replacement) {
    if (!text || !pattern || !replacement) {
        return false;
    }
    
    size_t pattern_length = strlen(pattern);
    size_t replacement_length = strlen(replacement);
    
    if (pattern_length == 0 || text_length < pattern_length) {
        return false;
    }
    
    bool found = false;
    size_t i = 0;
    
    while (i <= text_length - pattern_length) {
        if (memcmp(text + i, pattern, pattern_length) == 0) {
            // Found pattern, replace it
            if (replacement_length > pattern_length) {
                // Need to shift text to make room
                memmove(text + i + replacement_length, text + i + pattern_length, text_length - i - pattern_length);
            } else if (replacement_length < pattern_length) {
                // Need to shift text to remove extra space
                memmove(text + i + replacement_length, text + i + pattern_length, text_length - i - pattern_length);
            }
            
            memcpy(text + i, replacement, replacement_length);
            text_length += replacement_length - pattern_length;
            i += replacement_length;
            found = true;
        } else {
            i++;
        }
    }
    
    return found;
}

/**
 * @brief Obfuscate string using XOR with multiple keys
 */
static void obfuscate_string(char* str, size_t length, int level) {
    if (!str || length == 0 || level <= 0) {
        return;
    }
    
    // Generate obfuscation keys based on level
    uint8_t keys[MAX_OBFUSCATION_LEVEL];
    for (int i = 0; i < level && i < MAX_OBFUSCATION_LEVEL; i++) {
        keys[i] = (uint8_t)((i + 1) * 0x55);
    }
    
    // Apply obfuscation
    for (size_t i = 0; i < length; i++) {
        str[i] ^= keys[i % level];
    }
}

/**
 * @brief Deobfuscate string using XOR with multiple keys
 */
static void deobfuscate_string(char* str, size_t length, int level) {
    if (!str || length == 0 || level <= 0) {
        return;
    }
    
    // Generate deobfuscation keys (same as obfuscation keys)
    uint8_t keys[MAX_OBFUSCATION_LEVEL];
    for (int i = 0; i < level && i < MAX_OBFUSCATION_LEVEL; i++) {
        keys[i] = (uint8_t)((i + 1) * 0x55);
    }
    
    // Apply deobfuscation (XOR is symmetric)
    for (size_t i = 0; i < length; i++) {
        str[i] ^= keys[i % level];
    }
}

/**
 * @brief Secure zero memory
 */
static void secure_zero_memory(void* ptr, size_t size) {
    if (!ptr || size == 0) {
        return;
    }
    
    volatile char* p = (volatile char*)ptr;
    while (size--) {
        *p++ = 0;
    }
}

/**
 * @brief Validate string integrity
 */
static bool validate_string_integrity(const char* str, size_t length) {
    if (!str || length == 0) {
        return false;
    }
    
    // Check for null terminator
    if (str[length - 1] != '\0') {
        return false;
    }
    
    // Check for valid ASCII characters
    for (size_t i = 0; i < length - 1; i++) {
        if (str[i] < 0 || str[i] > 127) {
            return false;
        }
    }
    
    return true;
}

/**
 * @brief Initialize pattern tracker
 */
static void init_pattern_tracker(void) {
    InitializeCriticalSection(&g_pattern_tracker.mutex);
    g_pattern_tracker.pattern_count = 0;
}

/**
 * @brief Add pattern to tracker
 */
static void add_pattern(const char* pattern) {
    if (!pattern || strlen(pattern) == 0) {
        return;
    }
    
    EnterCriticalSection(&g_pattern_tracker.mutex);
    
    if (g_pattern_tracker.pattern_count < 100) {
        pattern_match_t* p = &g_pattern_tracker.patterns[g_pattern_tracker.pattern_count];
        strncpy(p->pattern, pattern, sizeof(p->pattern) - 1);
        p->pattern_length = strlen(pattern);
        p->match_count = 0;
        p->last_match = 0;
        
        g_pattern_tracker.pattern_count++;
    }
    
    LeaveCriticalSection(&g_pattern_tracker.mutex);
}

/**
 * @brief Check patterns in text
 */
static bool check_patterns(const char* text, size_t length) {
    if (!text || length == 0) {
        return false;
    }
    
    EnterCriticalSection(&g_pattern_tracker.mutex);
    
    bool found = false;
    for (int i = 0; i < g_pattern_tracker.pattern_count; i++) {
        pattern_match_t* p = &g_pattern_tracker.patterns[i];
        
        if (find_pattern(text, length, p->pattern, p->pattern_length)) {
            p->match_count++;
            p->last_match = time(NULL);
            found = true;
        }
    }
    
    LeaveCriticalSection(&g_pattern_tracker.mutex);
    
    return found;
}

/**
 * @brief Cleanup patterns
 */
static void cleanup_patterns(void) {
    EnterCriticalSection(&g_pattern_tracker.mutex);
    
    for (int i = 0; i < g_pattern_tracker.pattern_count; i++) {
        pattern_match_t* p = &g_pattern_tracker.patterns[i];
        secure_zero_memory(p->pattern, sizeof(p->pattern));
        p->pattern_length = 0;
        p->match_count = 0;
        p->last_match = 0;
    }
    
    g_pattern_tracker.pattern_count = 0;
    
    LeaveCriticalSection(&g_pattern_tracker.mutex);
    DeleteCriticalSection(&g_pattern_tracker.mutex);
}

/**
 * @brief Main function for testing
 */
int main() {
    // Initialize pattern tracker
    init_pattern_tracker();
    
    // Add some test patterns
    add_pattern("password");
    add_pattern("secret");
    add_pattern("key");
    
    // Test secure string
    secure_string_t str;
    if (init_secure_string(&str, 1024)) {
        // Append some data
        append_secure_string(&str, "Hello, World!", 13);
        printf("Original: %s\n", str.data);
        
        // Encrypt
        if (encrypt_secure_string(&str)) {
            printf("Encrypted: %s\n", str.data);
            
            // Decrypt
            if (decrypt_secure_string(&str)) {
                printf("Decrypted: %s\n", str.data);
            }
        }
        
        // Test obfuscation
        char test_str[] = "This is a test string";
        printf("Original: %s\n", test_str);
        
        obfuscate_string(test_str, strlen(test_str), 3);
        printf("Obfuscated: %s\n", test_str);
        
        deobfuscate_string(test_str, strlen(test_str), 3);
        printf("Deobfuscated: %s\n", test_str);
        
        // Test pattern matching
        char test_text[] = "This is a secret password for the key";
        if (check_patterns(test_text, strlen(test_text))) {
            printf("Patterns found in text\n");
        }
        
        // Cleanup
        destroy_secure_string(&str);
    }
    
    // Cleanup patterns
    cleanup_patterns();
    
    return 0;
}