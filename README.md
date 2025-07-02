# ProcHunter++ 🛠️

**Advanced Process Scanner & Rootkit Detection Tool for Linux**

Credits: [X2X0](https://github.com/X2X0)

## 🔍 Overview

ProcHunter++ is a sophisticated C++ security tool designed to detect suspicious processes, potential rootkits, and malicious activities on Linux systems. It combines multiple detection techniques to identify anomalous behavior that traditional process monitors might miss.

## ✨ Key Features

### Core Detection Capabilities
- **Process Enumeration**: Scans all active processes via `/proc` filesystem
- **Hash Verification**: Calculates SHA256 checksums and compares against trusted whitelist
- **Path Analysis**: Validates executable locations against trusted system paths
- **Memory Inspection**: Detects suspicious memory mappings and code injection
- **Pattern Matching**: Identifies processes matching known malware signatures
- **Hidden Process Detection**: Finds processes with name/cmdline mismatches

### Advanced Features
- **Suspicion Scoring**: Quantitative risk assessment for each process
- **Stealth Mode**: Silent operation until explicitly flagged
- **TUI Interface**: Real-time ncurses-based monitoring (like `htop`)
- **JSON Export**: Machine-readable output for integration with other tools
- **Process Termination**: Automatically kill highly suspicious processes
- **Memory Analysis**: Detect RWX regions, executable heaps, and deleted binaries in memory

## 🚀 Quick Start

### Prerequisites

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install build-essential libssl-dev libncurses5-dev libjsoncpp-dev
```

**RHEL/CentOS/Fedora:**
```bash
sudo yum install gcc-c++ openssl-devel ncurses-devel jsoncpp-devel
```

### Build & Install

```bash
# Clone and build
git clone https://github.com/X2X0/ProcHunter-
cd ProcHunter-
make

# Install system-wide
sudo make install

# Or build static version for forensic environments
make static
```

### Basic Usage

```bash
# Interactive TUI mode (recommended)
sudo prochunter --tui

# Quick scan with JSON output
sudo prochunter --json > scan_results.json

# Silent mode with automatic threat elimination
sudo prochunter --silent --kill --threshold 70

# Export detailed report
sudo prochunter --json | jq '.' > detailed_report.json
```

## 📋 Command Line Options

| Option | Description |
|--------|-------------|
| `-t, --tui` | Launch interactive Text User Interface |
| `-s, --silent` | Run in silent mode (no output until completion) |
| `-j, --json` | Export results in JSON format |
| `-k, --kill` | Terminate processes exceeding suspicion threshold |
| `--threshold NUM` | Set suspicion score threshold (default: 50) |
| `-h, --help` | Display help information |

## 🎯 Detection Methods

### 1. Signature-Based Detection
- Known malware process names
- Cryptocurrency miner patterns
- Fake kernel thread names
- Suspicious command line arguments

### 2. Behavioral Analysis
- Processes running from temporary directories
- Executables with missing or invalid paths
- Command line / process name mismatches
- Empty command lines for user processes

### 3. Memory Forensics
- RWX (Read-Write-Execute) memory regions
- Executable heap segments
- Deleted executables still running in memory
- Unusual memory mapping patterns

### 4. Hash Verification
- SHA256 checksum validation
- Comparison against trusted binary whitelist
- Detection of modified system binaries

## 📊 Suspicion Scoring System

ProcHunter++ assigns suspicion scores based on multiple factors:

| Factor | Score | Description |
|--------|-------|-------------|
| Suspicious pattern match | +30 | Process name matches known malware patterns |
| Untrusted location | +15 | Executable located outside trusted system paths |
| Deleted executable | +25 | Binary file deleted but still running in memory |
| Name/cmdline mismatch | +20 | Process name doesn't match command line |
| RWX memory regions | +20 | Writable and executable memory segments |
| Executable heap | +15 | Heap memory marked as executable |
| Empty command line | +15 | No command line arguments for user process |
| Unknown hash | +10 | SHA256 not in trusted whitelist |
| Unreadable executable | +10 | Cannot access process executable path |

**Threat Levels:**
- **0-39**: Low risk (Green)
- **40-69**: Moderate suspicion (Yellow)
- **70+**: High risk (Red) - Recommended for termination

## 🖥️ Interactive TUI Mode

The Text User Interface provides real-time monitoring with color-coded threat levels:

```
ProcHunter++ - Advanced Process Scanner
Credits: https://github.com/X2X0
========================================

PID     Name            Score   Anomalies                    Path
1234    suspicious_proc   85     RWX memory; Deleted exec    /tmp/malware
5678    crypto_miner     75     Pattern match; Untrusted    /dev/shm/miner
9012    normal_process   5      Hash verified               /usr/bin/vim
```

**TUI Controls:**
- `r` - Refresh scan
- `k` - Kill suspicious processes
- `q` - Quit

## 📁 File Structure

```
prochunter++/
├── src/
│   └── prochunter.cpp      # Main source code
├── build/                  # Build artifacts
├── bin/                    # Compiled binary
├── whitelist.txt          # Trusted binary hashes
├── Makefile               # Build configuration
└── README.md              # This file
```

## 🔧 Configuration Files

### Whitelist Management (`whitelist.txt`)
```bash
# Add trusted binary hashes
echo "$(sha256sum /bin/bash | cut -d' ' -f1)" >> whitelist.txt
echo "$(sha256sum /usr/bin/systemd | cut -d' ' -f1)" >> whitelist.txt
```

### Custom Suspicious Patterns
Edit the `initializeSuspiciousPatterns()` function to add custom detection rules:

```cpp
suspicious_patterns.push_back("your_malware_pattern");
suspicious_patterns.push_back("custom_threat_name");
```

## 🚨 Use Cases

### 1. Incident Response
```bash
# Quick forensic scan
sudo prochunter --silent --json > incident_$(date +%Y%m%d_%H%M%S).json

# Real-time monitoring during investigation
sudo prochunter --tui
```

### 2. System Hardening
```bash
# Regular security checks
sudo prochunter --threshold 40 --kill
```

### 3. Malware Analysis
```bash
# Detailed analysis with memory inspection
sudo prochunter --json | jq '.processes[] | select(.suspicion_score > 50)'
```

### 4. Continuous Monitoring
```bash
# Cron job for automated scanning
0 */6 * * * /usr/local/bin/prochunter --silent --json >> /var/log/prochunter.log
```

## 🔒 Security Considerations

### Permissions
- **Root access required** for full functionality
- Memory analysis requires elevated privileges
- Process termination needs administrative rights

### False Positives
- Legitimate software in unusual locations may trigger alerts
- Custom compiled applications might not be in whitelist
- Review results before using `--kill` option

### Evasion Resistance
- Multiple detection vectors make evasion difficult
- Memory analysis catches fileless malware
- Hash verification prevents binary modification

## 🛡️ Advanced Features

### Memory Forensics
ProcHunter++ analyzes `/proc/[pid]/maps` to detect:
- Code injection attempts
- Shellcode in memory
- Process hollowing
- Return-oriented programming (ROP) chains

### Rootkit Detection
Specialized checks for:
- Kernel module rootkits
- User-land rootkits
- Process hiding techniques
- System call hooking

### Performance Optimization
- Efficient filesystem scanning
- Minimal memory footprint
- Optimized hash calculations
- Parallel processing support

## 📊 JSON Output Format

```json
{
  "processes": [
    {
      "pid": 1234,
      "name": "suspicious_proc",
      "cmdline": "/tmp/malware --stealth",
      "exe_path": "/tmp/malware",
      "sha256_hash": "abc123...",
      "suspicion_score": 85,
      "is_hidden": false,
      "anomalies": [
        "RWX memory region detected",
        "Running from temporary directory",
        "Hash not in trusted whitelist"
      ]
    }
  ],
  "scan_time": 1625097600,
  "total_processes": 156
}
```

## 🔧 Build Options

### Static Build (Forensic Environment)
```bash
make static
```
Creates a statically-linked binary suitable for:
- LiveCD environments
- Air-gapped systems
- Forensic analysis
- Emergency response

### Debug Build
```bash
make debug
```
Includes debugging symbols and verbose output.

### Cross-Compilation
```bash
# For ARM64
make CXX=aarch64-linux-gnu-g++

# For 32-bit x86
make CXXFLAGS="-m32"
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit pull requests or report issues.
-
### Development Setup
```bash
git clone https://github.com/X2X0/ProcHunter-
cd ProcHunter-
make debug
```

### Adding Detection Rules
1. Edit `initializeSuspiciousPatterns()`
2. Add new scoring logic in `analyzeSuspicion()`
3. Test with `make test`

## 📜 License

This project is licensed under the MIT License - see the LICENSE file for details.

## ⚠️ Disclaimer

ProcHunter++ is designed for legitimate security research and system administration. Users are responsible for complying with all applicable laws and regulations. The tool should only be used on systems you own or have explicit permission to test.

## 🙏 Acknowledgments

- OpenSSL for cryptographic functions
- ncurses for terminal interface
- jsoncpp for JSON handling
- Linux kernel developers for the `/proc` filesystem

---

**Credits: [X2X0](https://github.com/X2X0)**

*ProcHunter++ - Because your processes deserve scrutiny* 🔍
