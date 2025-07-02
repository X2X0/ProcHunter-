#!/bin/bash
# ProcHunter++ Setup and Configuration Scripts
# Credits: https://github.com/X2X0

# =============================================================================
# whitelist_generator.sh - Generate trusted binary whitelist
# =============================================================================
cat > whitelist_generator.sh << 'EOF'
#!/bin/bash
# Whitelist Generator for ProcHunter++
# Credits: https://github.com/X2X0

WHITELIST_FILE="whitelist.txt"
SYSTEM_PATHS=("/bin" "/sbin" "/usr/bin" "/usr/sbin" "/lib" "/usr/lib" "/lib64" "/usr/lib64")

echo "# ProcHunter++ Trusted Binary Whitelist" > "$WHITELIST_FILE"
echo "# Generated on: $(date)" >> "$WHITELIST_FILE"
echo "# Credits: https://github.com/X2X0" >> "$WHITELIST_FILE"
echo "" >> "$WHITELIST_FILE"

echo "Generating whitelist for trusted system binaries..."

for path in "${SYSTEM_PATHS[@]}"; do
    if [ -d "$path" ]; then
        echo "Processing $path..."
        find "$path" -type f -executable 2>/dev/null | while read -r binary; do
            if [ -f "$binary" ] && [ -x "$binary" ]; then
                hash=$(sha256sum "$binary" 2>/dev/null | cut -d' ' -f1)
                if [ ! -z "$hash" ]; then
                    echo "$hash  # $(basename "$binary")" >> "$WHITELIST_FILE"
                fi
            fi
        done
    fi
done

echo "Whitelist generated: $WHITELIST_FILE"
echo "Total entries: $(grep -c '^[a-f0-9]' "$WHITELIST_FILE")"
EOF

chmod +x whitelist_generator.sh

# =============================================================================
# prochunter.conf - Configuration file
# =============================================================================
cat > prochunter.conf << 'EOF'
# ProcHunter++ Configuration File
# Credits: https://github.com/X2X0

[detection]
# Suspicion threshold (0-100)
threshold=50

# Enable memory analysis
memory_analysis=true

# Enable hash verification
hash_verification=true

# Enable pattern matching
pattern_matching=true

# Kill suspicious processes automatically
auto_kill=false

[paths]
# Trusted executable paths (colon-separated)
trusted_paths=/bin:/sbin:/usr/bin:/usr/sbin:/lib:/usr/lib:/lib64:/usr/lib64:/opt

# Whitelist file location
whitelist_file=whitelist.txt

# Log file location
log_file=/var/log/prochunter.log

[output]
# Default output format (text|json|tui)
format=text

# Enable colors in text output
colors=true

# Silent mode by default
silent=false

[suspicious_patterns]
# Cryptocurrency miners
patterns=minerd,xmrig,cryptonight,stratum,cpuminer

# Fake kernel threads
kernel_fakes=kthreadd,ksoftirqd,migration,rcu_,watchdog

# Common malware names
malware_names=backdoor,trojan,rootkit,keylogger

[advanced]
# Enable ptrace for memory analysis
use_ptrace=true

# Maximum processes to scan (0 = unlimited)
max_processes=0

# Scan interval in TUI mode (seconds)
refresh_interval=5

# Enable network connection analysis
network_analysis=false
EOF

# =============================================================================
# install_dependencies.sh - Dependency installer
# =============================================================================
cat > install_dependencies.sh << 'EOF'
#!/bin/bash
# ProcHunter++ Dependency Installer
# Credits: https://github.com/X2X0

set -e

echo "ProcHunter++ Dependency Installer"
echo "================================="

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    VERSION=$VERSION_ID
else
    echo "Cannot detect OS. Please install dependencies manually."
    exit 1
fi

echo "Detected OS: $OS $VERSION"

case $OS in
    ubuntu|debian)
        echo "Installing dependencies for Ubuntu/Debian..."
        sudo apt-get update
        sudo apt-get install -y \
            build-essential \
            g++ \
            libssl-dev \
            libncurses5-dev \
            libjsoncpp-dev \
            pkg-config \
            git \
            make
        ;;
    
    fedora|rhel|centos)
        echo "Installing dependencies for RHEL/CentOS/Fedora..."
        if command -v dnf > /dev/null; then
            sudo dnf install -y \
                gcc-c++ \
                openssl-devel \
                ncurses-devel \
                jsoncpp-devel \
                pkgconfig \
                git \
                make
        else
            sudo yum install -y \
                gcc-c++ \
                openssl-devel \
                ncurses-devel \
                jsoncpp-devel \
                pkgconfig \
                git \
                make
        fi
        ;;
    
    arch)
        echo "Installing dependencies for Arch Linux..."
        sudo pacman -S --needed \
            gcc \
            openssl \
            ncurses \
            jsoncpp \
            pkgconf \
            git \
            make
        ;;
    
    alpine)
        echo "Installing dependencies for Alpine Linux..."
        sudo apk add \
            build-base \
            g++ \
            openssl-dev \
            ncurses-dev \
            jsoncpp-dev \
            pkgconfig \
            git \
            make
        ;;
    
    *)
        echo "Unsupported OS: $OS"
        echo "Please install the following packages manually:"
        echo "- build-essential / gcc-c++"
        echo "- libssl-dev / openssl-devel"
        echo "- libncurses5-dev / ncurses-devel"
        echo "- libjsoncpp-dev / jsoncpp-devel"
        echo "- pkg-config / pkgconfig"
        exit 1
        ;;
esac

echo "Dependencies installed successfully!"
echo "You can now build ProcHunter++ with: make"
EOF

chmod +x install_dependencies.sh

# =============================================================================
# systemd service file
# =============================================================================
cat > prochunter.service << 'EOF'
[Unit]
Description=ProcHunter++ Process Monitor
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/prochunter --silent --json
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# =============================================================================
# Cron job setup script
# =============================================================================
cat > setup_cron.sh << 'EOF'
#!/bin/bash
# Setup cron job for ProcHunter++
# Credits: https://github.com/X2X0

CRON_FILE="/etc/cron.d/prochunter"

cat > $CRON_FILE << 'CRONEOF'
# ProcHunter++ Automated Security Scan
# Credits: https://github.com/X2X0

# Run every 6 hours
0 */6 * * * root /usr/local/bin/prochunter --silent --json >> /var/log/prochunter.log 2>&1

# Weekly full scan with cleanup
0 2 * * 0 root /usr/local/bin/prochunter --kill --threshold 70 --silent >> /var/log/prochunter-weekly.log 2>&1
CRONEOF

echo "Cron job installed: $CRON_FILE"
echo "ProcHunter++ will run automatically every 6 hours"
EOF

chmod +x setup_cron.sh

# =============================================================================
# Forensic analysis script
# =============================================================================
cat > forensic_scan.sh << 'EOF'
#!/bin/bash
# ProcHunter++ Forensic Analysis Script
# Credits: https://github.com/X2X0

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT_DIR="prochunter_forensic_$TIMESTAMP"
BINARY="./bin/prochunter"

# Check if binary exists
if [ ! -f "$BINARY" ]; then
    echo "Error: ProcHunter++ binary not found at $BINARY"
    echo "Please build the project first: make"
    exit 1
fi

echo "ProcHunter++ Forensic Analysis"
echo "=============================="
echo "Timestamp: $(date)"
echo "Host: $(hostname)"
echo "Kernel: $(uname -a)"
echo

# Create report directory
mkdir -p "$REPORT_DIR"

echo "Generating forensic report in: $REPORT_DIR"

# Basic system info
echo "Collecting system information..."
cat > "$REPORT_DIR/system_info.txt" << SYSEOF
System Information - $(date)
============================
Hostname: $(hostname)
Kernel: $(uname -a)
Uptime: $(uptime)
Load Average: $(cat /proc/loadavg)
Memory: $(free -h)
Disk Usage: $(df -h)
Network Interfaces: $(ip addr show)
SYSEOF

# Run ProcHunter++ scan
echo "Running ProcHunter++ scan..."
sudo "$BINARY" --json > "$REPORT_DIR/prochunter_scan.json" 2>&1

# Extract suspicious processes
echo "Analyzing results..."
if command -v jq > /dev/null; then
    jq '.processes[] | select(.suspicion_score > 40)' "$REPORT_DIR/prochunter_scan.json" > "$REPORT_DIR/suspicious_processes.json"
    echo "Found $(jq '.processes[] | select(.suspicion_score > 40) | .pid' "$REPORT_DIR/prochunter_scan.json" | wc -l) suspicious processes"
else
    echo "jq not installed - raw JSON data available in prochunter_scan.json"
fi

# Collect additional forensic data
echo "Collecting additional forensic data..."

# Process tree
ps auxf > "$REPORT_DIR/process_tree.txt"

# Network connections
netstat -tulpn > "$REPORT_DIR/network_connections.txt" 2>&1

# Open files
lsof > "$REPORT_DIR/open_files.txt" 2>&1

# Loaded modules
lsmod > "$REPORT_DIR/loaded_modules.txt"

# System logs (last 1000 lines)
tail -1000 /var/log/syslog > "$REPORT_DIR/recent_syslog.txt" 2>/dev/null || \
tail -1000 /var/log/messages > "$REPORT_DIR/recent_messages.txt" 2>/dev/null

# Create archive
echo "Creating forensic archive..."
tar -czf "forensic_report_$TIMESTAMP.tar.gz" "$REPORT_DIR"

echo
echo "Forensic analysis complete!"
echo "Report directory: $REPORT_DIR"
echo "Archive: forensic_report_$TIMESTAMP.tar.gz"
echo
echo "Review suspicious processes with:"
echo "jq '.processes[] | select(.suspicion_score > 40)' $REPORT_DIR/prochunter_scan.json"
EOF

chmod +x forensic_scan.sh

# =============================================================================
# Performance benchmark script
# =============================================================================
cat > benchmark.sh << 'EOF'
#!/bin/bash
# ProcHunter++ Performance Benchmark
# Credits: https://github.com/X2X0

BINARY="./bin/prochunter"
ITERATIONS=5

if [ ! -f "$BINARY" ]; then
    echo "Error: ProcHunter++ binary not found"
    echo "Please build the project first: make"
    exit 1
fi

echo "ProcHunter++ Performance Benchmark"
echo "=================================="
echo "Binary: $BINARY"
echo "Iterations: $ITERATIONS"
echo "System: $(uname -a)"
echo

total_time=0
total_processes=0

for i in $(seq 1 $ITERATIONS); do
    echo "Run $i/$ITERATIONS..."
    
    start_time=$(date +%s.%N)
    result=$(sudo "$BINARY" --silent --json)
    end_time=$(date +%s.%N)
    
    duration=$(echo "$end_time - $start_time" | bc)
    processes=$(echo "$result" | jq -r '.total_processes' 2>/dev/null || echo "0")
    
    echo "  Duration: ${duration}s"
    echo "  Processes: $processes"
    
    total_time=$(echo "$total_time + $duration" | bc)
    total_processes=$((total_processes + processes))
done

avg_time=$(echo "scale=3; $total_time / $ITERATIONS" | bc)
avg_processes=$((total_processes / ITERATIONS))

echo
echo "Benchmark Results:"
echo "=================="
echo "Average scan time: ${avg_time}s"
echo "Average processes scanned: $avg_processes"
echo "Processes per second: $(echo "scale=2; $avg_processes / $avg_time" | bc)"
EOF

chmod +x benchmark.sh

echo "Configuration files and scripts created successfully!"
echo "Files created:"
echo "- whitelist_generator.sh  (Generate trusted binary whitelist)"
echo "- prochunter.conf         (Main configuration file)"
echo "- install_dependencies.sh (Install build dependencies)"
echo "- prochunter.service      (Systemd service file)"
echo "- setup_cron.sh          (Setup automated scanning)"
echo "- forensic_scan.sh       (Complete forensic analysis)"
echo "- benchmark.sh           (Performance testing)"
echo
echo "To get started:"
echo "1. Run: ./install_dependencies.sh"
echo "2. Run: make"
echo "3. Run: ./whitelist_generator.sh"
echo "4. Run: sudo ./bin/prochunter --tui"
