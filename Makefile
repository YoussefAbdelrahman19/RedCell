# RedCell - Advanced Penetration Testing Framework
# Professional Makefile for Windows/Linux cross-compilation

# Compiler settings
CC = gcc
CXX = g++
WINCC = x86_64-w64-mingw32-gcc
WINCXX = x86_64-w64-mingw32-g++

# Project information
PROJECT_NAME = RedCell
VERSION = 2.0
AUTHOR = Youssef Abdelrahman

# Directories
SRC_DIR = src
INC_DIR = include
BUILD_DIR = build
DIST_DIR = dist
DOCS_DIR = docs
TEST_DIR = tests

# Source files
CORE_SOURCES = backdoor_V2.c server_V2.c
TEST_SOURCES = backdoortest_V2.c sertest_V2.c
UTIL_SOURCES = str_cut+function_V2.c
HEADERS = keylogger_V2.h keylogger.h

# Output files
BACKDOOR_TARGET = $(BUILD_DIR)/redcell_client
SERVER_TARGET = $(BUILD_DIR)/redcell_server
TEST_TARGET = $(BUILD_DIR)/redcell_test

# Windows targets
WIN_BACKDOOR_TARGET = $(BUILD_DIR)/redcell_client.exe
WIN_SERVER_TARGET = $(BUILD_DIR)/redcell_server.exe
WIN_TEST_TARGET = $(BUILD_DIR)/redcell_test.exe

# Compiler flags
CFLAGS = -Wall -Wextra -std=c99 -O2
DEBUG_CFLAGS = -Wall -Wextra -std=c99 -g -DDEBUG -O0
RELEASE_CFLAGS = -Wall -Wextra -std=c99 -O3 -DNDEBUG -s

# Windows specific flags
WIN_CFLAGS = -Wall -Wextra -std=c99 -O2 -DWIN32 -D_WIN32_WINNT=0x0601
WIN_LDFLAGS = -lws2_32 -ladvapi32 -lpsapi -lntdll -static-libgcc -static-libstdc++

# Linux specific flags
LINUX_CFLAGS = -Wall -Wextra -std=c99 -O2 -DLINUX
LINUX_LDFLAGS = -lpthread -lssl -lcrypto

# Include paths
INCLUDES = -I$(INC_DIR) -I/usr/local/include -I/usr/include/openssl

# Library paths
LIB_PATHS = -L/usr/local/lib -L/usr/lib

# Colors for output
RED = \033[31m
GREEN = \033[32m
YELLOW = \033[33m
BLUE = \033[34m
MAGENTA = \033[35m
CYAN = \033[36m
WHITE = \033[37m
RESET = \033[0m

# Default target
.PHONY: all clean install uninstall test windows linux debug release help

all: info directories linux windows

# Display project information
info:
	@echo "$(CYAN)========================================$(RESET)"
	@echo "$(MAGENTA)  $(PROJECT_NAME) v$(VERSION) Build System$(RESET)"
	@echo "$(CYAN)  Author: $(AUTHOR)$(RESET)"
	@echo "$(CYAN)========================================$(RESET)"
	@echo "$(GREEN)Building advanced penetration testing framework...$(RESET)"

# Create necessary directories
directories:
	@mkdir -p $(BUILD_DIR) $(DIST_DIR) $(SRC_DIR) $(INC_DIR) $(DOCS_DIR) $(TEST_DIR)
	@echo "$(GREEN)[INFO] Created build directories$(RESET)"

# Linux builds
linux: $(BACKDOOR_TARGET) $(SERVER_TARGET)
	@echo "$(GREEN)[SUCCESS] Linux build completed$(RESET)"

$(BACKDOOR_TARGET): backdoor_V2.c $(HEADERS)
	@echo "$(YELLOW)[BUILD] Compiling Linux backdoor...$(RESET)"
	$(CC) $(LINUX_CFLAGS) $(INCLUDES) -o $@ backdoor_V2.c $(LIB_PATHS) $(LINUX_LDFLAGS)
	@echo "$(GREEN)[OK] Linux backdoor compiled$(RESET)"

$(SERVER_TARGET): server_V2.c $(HEADERS)
	@echo "$(YELLOW)[BUILD] Compiling Linux server...$(RESET)"
	$(CC) $(LINUX_CFLAGS) $(INCLUDES) -o $@ server_V2.c $(LIB_PATHS) $(LINUX_LDFLAGS)
	@echo "$(GREEN)[OK] Linux server compiled$(RESET)"

# Windows builds
windows: $(WIN_BACKDOOR_TARGET) $(WIN_SERVER_TARGET)
	@echo "$(GREEN)[SUCCESS] Windows build completed$(RESET)"

$(WIN_BACKDOOR_TARGET): backdoor_V2.c $(HEADERS)
	@echo "$(YELLOW)[BUILD] Cross-compiling Windows backdoor...$(RESET)"
	$(WINCC) $(WIN_CFLAGS) $(INCLUDES) -o $@ backdoor_V2.c $(WIN_LDFLAGS)
	@echo "$(GREEN)[OK] Windows backdoor compiled$(RESET)"

$(WIN_SERVER_TARGET): server_V2.c $(HEADERS)
	@echo "$(YELLOW)[BUILD] Cross-compiling Windows server...$(RESET)"
	$(WINCC) $(WIN_CFLAGS) $(INCLUDES) -o $@ server_V2.c $(WIN_LDFLAGS)
	@echo "$(GREEN)[OK] Windows server compiled$(RESET)"

# Debug builds
debug: CFLAGS = $(DEBUG_CFLAGS)
debug: WIN_CFLAGS += -DDEBUG -g
debug: directories
	@echo "$(MAGENTA)[DEBUG] Building debug version...$(RESET)"
	$(CC) $(DEBUG_CFLAGS) $(INCLUDES) -o $(BUILD_DIR)/redcell_debug backdoor_V2.c $(LINUX_LDFLAGS)
	@echo "$(GREEN)[OK] Debug build completed$(RESET)"

# Release builds
release: CFLAGS = $(RELEASE_CFLAGS)
release: WIN_CFLAGS = $(WIN_CFLAGS) -O3 -DNDEBUG -s
release: directories linux windows
	@echo "$(GREEN)[RELEASE] Packaging release...$(RESET)"
	@mkdir -p $(DIST_DIR)/linux $(DIST_DIR)/windows
	@cp $(BUILD_DIR)/redcell_* $(DIST_DIR)/linux/
	@cp $(BUILD_DIR)/*.exe $(DIST_DIR)/windows/
	@tar -czf $(DIST_DIR)/RedCell-v$(VERSION)-linux.tar.gz -C $(DIST_DIR)/linux .
	@zip -r $(DIST_DIR)/RedCell-v$(VERSION)-windows.zip $(DIST_DIR)/windows/
	@echo "$(GREEN)[SUCCESS] Release packages created in $(DIST_DIR)/$(RESET)"

# Testing
test: $(TEST_TARGET)
	@echo "$(BLUE)[TEST] Running test suite...$(RESET)"
	./$(TEST_TARGET)
	@echo "$(GREEN)[OK] Tests completed$(RESET)"

$(TEST_TARGET): $(TEST_SOURCES) $(HEADERS)
	@echo "$(YELLOW)[BUILD] Compiling test suite...$(RESET)"
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $(TEST_SOURCES) $(LINUX_LDFLAGS)

# Code analysis
analyze:
	@echo "$(BLUE)[ANALYSIS] Running static code analysis...$(RESET)"
	@if command -v cppcheck >/dev/null 2>&1; then \
		cppcheck --enable=all --std=c99 *.c *.h; \
	else \
		echo "$(YELLOW)[WARNING] cppcheck not found, skipping analysis$(RESET)"; \
	fi

# Code formatting
format:
	@echo "$(BLUE)[FORMAT] Formatting code...$(RESET)"
	@if command -v clang-format >/dev/null 2>&1; then \
		clang-format -i *.c *.h; \
		echo "$(GREEN)[OK] Code formatted$(RESET)"; \
	else \
		echo "$(YELLOW)[WARNING] clang-format not found$(RESET)"; \
	fi

# Documentation
docs:
	@echo "$(BLUE)[DOCS] Generating documentation...$(RESET)"
	@if command -v doxygen >/dev/null 2>&1; then \
		doxygen Doxyfile; \
		echo "$(GREEN)[OK] Documentation generated in $(DOCS_DIR)/$(RESET)"; \
	else \
		echo "$(YELLOW)[WARNING] doxygen not found$(RESET)"; \
	fi

# Security scan
security:
	@echo "$(RED)[SECURITY] Running security analysis...$(RESET)"
	@if command -v flawfinder >/dev/null 2>&1; then \
		flawfinder *.c *.h; \
	else \
		echo "$(YELLOW)[WARNING] flawfinder not found$(RESET)"; \
	fi

# Clean build artifacts
clean:
	@echo "$(RED)[CLEAN] Removing build artifacts...$(RESET)"
	@rm -rf $(BUILD_DIR) $(DIST_DIR)
	@echo "$(GREEN)[OK] Cleanup completed$(RESET)"

# Install (for development)
install: release
	@echo "$(BLUE)[INSTALL] Installing RedCell...$(RESET)"
	@mkdir -p /opt/redcell/bin
	@mkdir -p /opt/redcell/docs
	@cp $(DIST_DIR)/linux/* /opt/redcell/bin/
	@cp README.md /opt/redcell/docs/
	@chmod +x /opt/redcell/bin/*
	@echo "$(GREEN)[OK] RedCell installed to /opt/redcell/$(RESET)"

# Uninstall
uninstall:
	@echo "$(RED)[UNINSTALL] Removing RedCell...$(RESET)"
	@rm -rf /opt/redcell
	@echo "$(GREEN)[OK] RedCell uninstalled$(RESET)"

# Show help
help:
	@echo "$(CYAN)RedCell v$(VERSION) Build System$(RESET)"
	@echo "$(WHITE)Available targets:$(RESET)"
	@echo "  $(GREEN)all$(RESET)        - Build all targets (Linux + Windows)"
	@echo "  $(GREEN)linux$(RESET)      - Build Linux targets"
	@echo "  $(GREEN)windows$(RESET)    - Build Windows targets (requires MinGW)"
	@echo "  $(GREEN)debug$(RESET)      - Build debug version"
	@echo "  $(GREEN)release$(RESET)    - Build optimized release with packages"
	@echo "  $(GREEN)test$(RESET)       - Build and run test suite"
	@echo "  $(GREEN)analyze$(RESET)    - Run static code analysis"
	@echo "  $(GREEN)format$(RESET)     - Format source code"
	@echo "  $(GREEN)docs$(RESET)       - Generate documentation"
	@echo "  $(GREEN)security$(RESET)   - Run security analysis"
	@echo "  $(GREEN)clean$(RESET)      - Remove build artifacts"
	@echo "  $(GREEN)install$(RESET)    - Install to system (requires sudo)"
	@echo "  $(GREEN)uninstall$(RESET)  - Remove from system (requires sudo)"
	@echo "  $(GREEN)help$(RESET)       - Show this help message"
	@echo ""
	@echo "$(YELLOW)Examples:$(RESET)"
	@echo "  make all          # Build everything"
	@echo "  make debug        # Build debug version"
	@echo "  make release      # Create release packages"
	@echo "  make test         # Run tests"
	@echo "  sudo make install # Install system-wide"

# Version information
version:
	@echo "$(PROJECT_NAME) v$(VERSION)"
	@echo "Author: $(AUTHOR)"
	@echo "Build system: Professional Makefile"

# Environment check
env:
	@echo "$(BLUE)[ENV] Checking build environment...$(RESET)"
	@echo "CC: $(shell which $(CC) || echo 'Not found')"
	@echo "MinGW: $(shell which $(WINCC) || echo 'Not found')"
	@echo "OpenSSL: $(shell pkg-config --modversion openssl 2>/dev/null || echo 'Not found')"
	@echo "Python: $(shell python3 --version 2>/dev/null || echo 'Not found')"
	@echo "Git: $(shell git --version 2>/dev/null || echo 'Not found')"

# Dependency check
deps:
	@echo "$(BLUE)[DEPS] Checking dependencies...$(RESET)"
	@echo "Checking for required libraries..."
	@pkg-config --exists openssl && echo "$(GREEN)[OK] OpenSSL found$(RESET)" || echo "$(RED)[ERROR] OpenSSL not found$(RESET)"
	@ldconfig -p | grep -q libssl && echo "$(GREEN)[OK] libssl found$(RESET)" || echo "$(RED)[ERROR] libssl not found$(RESET)"
	@ldconfig -p | grep -q libcrypto && echo "$(GREEN)[OK] libcrypto found$(RESET)" || echo "$(RED)[ERROR] libcrypto not found$(RESET)"

# Quick build for development
quick:
	@echo "$(YELLOW)[QUICK] Quick development build...$(RESET)"
	$(CC) $(CFLAGS) -o $(BUILD_DIR)/redcell_quick backdoor_V2.c $(LINUX_LDFLAGS)
	@echo "$(GREEN)[OK] Quick build completed$(RESET)"

# Strip binaries
strip: linux windows
	@echo "$(BLUE)[STRIP] Stripping debug symbols...$(RESET)"
	@strip $(BUILD_DIR)/redcell_* 2>/dev/null || true
	@x86_64-w64-mingw32-strip $(BUILD_DIR)/*.exe 2>/dev/null || true
	@echo "$(GREEN)[OK] Binaries stripped$(RESET)"

# Package for distribution
package: release
	@echo "$(BLUE)[PACKAGE] Creating distribution packages...$(RESET)"
	@mkdir -p $(DIST_DIR)/RedCell-v$(VERSION)
	@cp README.md LICENSE $(DIST_DIR)/RedCell-v$(VERSION)/
	@cp -r $(BUILD_DIR) $(DIST_DIR)/RedCell-v$(VERSION)/
	@tar -czf $(DIST_DIR)/RedCell-v$(VERSION)-complete.tar.gz -C $(DIST_DIR) RedCell-v$(VERSION)
	@echo "$(GREEN)[OK] Complete package created$(RESET)"

# Print build statistics
stats:
	@echo "$(CYAN)Project Statistics:$(RESET)"
	@echo "Total source files: $(shell find . -name '*.c' | wc -l)"
	@echo "Total header files: $(shell find . -name '*.h' | wc -l)"
	@echo "Total lines of code: $(shell find . -name '*.c' -o -name '*.h' | xargs wc -l | tail -n 1)"
	@echo "Project size: $(shell du -sh . | cut -f1)"

# Initialize development environment
init:
	@echo "$(BLUE)[INIT] Initializing development environment...$(RESET)"
	@mkdir -p $(SRC_DIR) $(INC_DIR) $(BUILD_DIR) $(DOCS_DIR) $(TEST_DIR)
	@echo "$(GREEN)[OK] Development environment initialized$(RESET)"

# Show targets
list:
	@echo "$(CYAN)Available build targets:$(RESET)"
	@$(MAKE) -qp | awk -F':' '/^[a-zA-Z0-9][^$$#\/\t=]*:([^=]|$$)/ {split($$1,A,/ /);for(i in A)print A[i]}' | grep -v Makefile | sort | uniq

# Advanced: Create installer
installer: package
	@echo "$(BLUE)[INSTALLER] Creating installation script...$(RESET)"
	@echo '#!/bin/bash' > $(DIST_DIR)/install.sh
	@echo 'echo "Installing RedCell v$(VERSION)..."' >> $(DIST_DIR)/install.sh
	@echo 'sudo mkdir -p /opt/redcell' >> $(DIST_DIR)/install.sh
	@echo 'sudo cp -r * /opt/redcell/' >> $(DIST_DIR)/install.sh
	@echo 'sudo chmod +x /opt/redcell/build/*' >> $(DIST_DIR)/install.sh
	@echo 'echo "RedCell installed successfully!"' >> $(DIST_DIR)/install.sh
	@chmod +x $(DIST_DIR)/install.sh
	@echo "$(GREEN)[OK] Installer created: $(DIST_DIR)/install.sh$(RESET)"

# Backup source code
backup:
	@echo "$(BLUE)[BACKUP] Creating source backup...$(RESET)"
	@mkdir -p backups
	@tar -czf backups/redcell-source-$(shell date +%Y%m%d-%H%M%S).tar.gz *.c *.h Makefile README.md
	@echo "$(GREEN)[OK] Backup created in backups/$(RESET)"