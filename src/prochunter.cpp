#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <algorithm>
#include <filesystem>
#include <thread>
#include <chrono>
#include <cstdlib>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <signal.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <ncurses.h>
#include <json/json.h>
#include <iomanip>
#include <sstream>

namespace fs = std::filesystem;

class ProcHunter {
private:
    struct ProcessInfo {
        int pid;
        std::string name;
        std::string cmdline;
        std::string exe_path;
        std::string sha256_hash;
        int suspicion_score;
        std::vector<std::string> anomalies;
        bool is_hidden;
        std::map<std::string, std::string> memory_maps;
    };

    std::vector<ProcessInfo> processes;
    std::set<std::string> whitelist_hashes;
    std::set<std::string> trusted_paths;
    std::vector<std::string> suspicious_patterns;
    bool silent_mode;
    bool tui_mode;
    bool json_output;
    int detection_threshold;

    // Colors for TUI
    enum Colors {
        COLOR_NORMAL = 1,
        COLOR_SUSPICIOUS = 2,
        COLOR_CRITICAL = 3,
        COLOR_SAFE = 4,
        COLOR_HEADER = 5
    };

public:
    ProcHunter() : silent_mode(false), tui_mode(false), json_output(false), detection_threshold(50) {
        initializeWhitelist();
        initializeTrustedPaths();
        initializeSuspiciousPatterns();
    }

    void printBanner() {
        if (silent_mode) return;
        
        std::cout << R"(
    ____                 __  __             __              ____   ____
   / __ \_________  ____/ / / /_  ______  / /____  _____  / __ \ / __ \
  / /_/ / ___/ __ \/ __/ /_/ / / / / __ \/ __/ _ \/ ___/ / /_/ // /_/ /
 / ____/ /  / /_/ / /_/ __  / /_/ / / / / /_/  __/ /    / ____// ____/ 
/_/   /_/   \____/\__/_/ /_/\__,_/_/ /_/\__/\___/_/    /_/    /_/      
                                                                        
Advanced Process Scanner & Rootkit Detection Tool
Credits: https://github.com/X2X0
========================================================
)" << std::endl;
    }

    void initializeWhitelist() {
        // Common system binaries SHA256 hashes (examples)
        whitelist_hashes.insert("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"); // systemd
        whitelist_hashes.insert("a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3"); // bash
        whitelist_hashes.insert("2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"); // sh
        // Add more known good hashes here
    }

    void initializeTrustedPaths() {
        trusted_paths.insert("/bin/");
        trusted_paths.insert("/sbin/");
        trusted_paths.insert("/usr/bin/");
        trusted_paths.insert("/usr/sbin/");
        trusted_paths.insert("/lib/");
        trusted_paths.insert("/usr/lib/");
        trusted_paths.insert("/lib64/");
        trusted_paths.insert("/usr/lib64/");
        trusted_paths.insert("/opt/");
    }

    void initializeSuspiciousPatterns() {
        suspicious_patterns.push_back("kthreadd");  // Fake kernel threads
        suspicious_patterns.push_back("ksoftirqd"); // Fake kernel processes
        suspicious_patterns.push_back("migration");
        suspicious_patterns.push_back("rcu_");
        suspicious_patterns.push_back("watchdog");
        suspicious_patterns.push_back("minerd");    // Cryptocurrency miners
        suspicious_patterns.push_back("xmrig");
        suspicious_patterns.push_back("cryptonight");
        suspicious_patterns.push_back("stratum");
    }

    std::string calculateSHA256(const std::string& filepath) {
        std::ifstream file(filepath, std::ios::binary);
        if (!file) return "";

        EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
        const EVP_MD *md = EVP_sha256();
        EVP_DigestInit_ex(mdctx, md, NULL);

        char buffer[8192];
        while (file.read(buffer, sizeof(buffer))) {
            EVP_DigestUpdate(mdctx, buffer, file.gcount());
        }
        if (file.gcount() > 0) {
            EVP_DigestUpdate(mdctx, buffer, file.gcount());
        }

        unsigned char hash[EVP_MAX_MD_SIZE];
        unsigned int hash_len;
        EVP_DigestFinal_ex(mdctx, hash, &hash_len);
        EVP_MD_CTX_free(mdctx);

        std::stringstream ss;
        for (unsigned int i = 0; i < hash_len; i++) {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
        }
        return ss.str();
    }

    bool isPathTrusted(const std::string& path) {
        for (const auto& trusted : trusted_paths) {
            if (path.find(trusted) == 0) {
                return true;
            }
        }
        return false;
    }

    bool matchesSuspiciousPattern(const std::string& name) {
        for (const auto& pattern : suspicious_patterns) {
            if (name.find(pattern) != std::string::npos) {
                return true;
            }
        }
        return false;
    }

    std::string readFile(const std::string& filepath) {
        std::ifstream file(filepath);
        if (!file) return "";
        std::string content((std::istreambuf_iterator<char>(file)),
                           std::istreambuf_iterator<char>());
        return content;
    }

    void analyzeMemoryMaps(ProcessInfo& proc) {
        std::string maps_path = "/proc/" + std::to_string(proc.pid) + "/maps";
        std::ifstream maps_file(maps_path);
        std::string line;
        
        while (std::getline(maps_file, line)) {
            if (line.find("rwx") != std::string::npos) {
                proc.suspicion_score += 20;
                proc.anomalies.push_back("RWX memory region detected");
            }
            if (line.find("[heap]") != std::string::npos && line.find("x") != std::string::npos) {
                proc.suspicion_score += 15;
                proc.anomalies.push_back("Executable heap detected");
            }
            if (line.find("(deleted)") != std::string::npos) {
                proc.suspicion_score += 25;
                proc.anomalies.push_back("Deleted executable in memory");
            }
        }
    }

    void scanProcesses() {
        processes.clear();
        
        for (const auto& entry : fs::directory_iterator("/proc")) {
            if (!entry.is_directory()) continue;
            
            std::string dirname = entry.path().filename();
            if (!std::all_of(dirname.begin(), dirname.end(), ::isdigit)) continue;
            
            int pid = std::stoi(dirname);
            ProcessInfo proc;
            proc.pid = pid;
            proc.suspicion_score = 0;
            proc.is_hidden = false;

            // Read process name
            std::string comm_path = "/proc/" + dirname + "/comm";
            proc.name = readFile(comm_path);
            if (!proc.name.empty() && proc.name.back() == '\n') {
                proc.name.pop_back();
            }

            // Read command line
            std::string cmdline_path = "/proc/" + dirname + "/cmdline";
            proc.cmdline = readFile(cmdline_path);
            std::replace(proc.cmdline.begin(), proc.cmdline.end(), '\0', ' ');

            // Read executable path
            std::string exe_path = "/proc/" + dirname + "/exe";
            try {
                proc.exe_path = fs::read_symlink(exe_path);
            } catch (...) {
                proc.exe_path = "";
                proc.suspicion_score += 10;
                proc.anomalies.push_back("Cannot read executable path");
            }

            // Calculate hash if executable exists
            if (!proc.exe_path.empty() && fs::exists(proc.exe_path)) {
                proc.sha256_hash = calculateSHA256(proc.exe_path);
            }

            // Analyze suspicion factors
            analyzeSuspicion(proc);
            
            // Analyze memory maps
            analyzeMemoryMaps(proc);

            processes.push_back(proc);
        }
    }

    void analyzeSuspicion(ProcessInfo& proc) {
        // Check if process name matches suspicious patterns
        if (matchesSuspiciousPattern(proc.name)) {
            proc.suspicion_score += 30;
            proc.anomalies.push_back("Matches suspicious pattern");
        }

        // Check if executable path is not trusted
        if (!proc.exe_path.empty() && !isPathTrusted(proc.exe_path)) {
            proc.suspicion_score += 15;
            proc.anomalies.push_back("Executable in untrusted location");
        }

        // Check if hash is not in whitelist
        if (!proc.sha256_hash.empty() && 
            whitelist_hashes.find(proc.sha256_hash) == whitelist_hashes.end()) {
            proc.suspicion_score += 10;
            proc.anomalies.push_back("Hash not in trusted whitelist");
        }

        // Check for hidden processes (name vs cmdline mismatch)
        if (!proc.name.empty() && !proc.cmdline.empty()) {
            if (proc.cmdline.find(proc.name) == std::string::npos) {
                proc.suspicion_score += 20;
                proc.anomalies.push_back("Process name/cmdline mismatch");
            }
        }

        // Check for processes with empty command line
        if (proc.cmdline.empty() && proc.pid > 2) {
            proc.suspicion_score += 15;
            proc.anomalies.push_back("Empty command line");
        }

        // Check for processes running from /tmp or /var/tmp
        if (proc.exe_path.find("/tmp/") == 0 || proc.exe_path.find("/var/tmp/") == 0) {
            proc.suspicion_score += 25;
            proc.anomalies.push_back("Running from temporary directory");
        }
    }

    void initializeTUI() {
        initscr();
        cbreak();
        noecho();
        keypad(stdscr, TRUE);
        timeout(1000);
        
        start_color();
        init_pair(COLOR_NORMAL, COLOR_WHITE, COLOR_BLACK);
        init_pair(COLOR_SUSPICIOUS, COLOR_YELLOW, COLOR_BLACK);
        init_pair(COLOR_CRITICAL, COLOR_RED, COLOR_BLACK);
        init_pair(COLOR_SAFE, COLOR_GREEN, COLOR_BLACK);
        init_pair(COLOR_HEADER, COLOR_CYAN, COLOR_BLACK);
    }

    void displayTUI() {
        clear();
        
        // Header
        attron(COLOR_PAIR(COLOR_HEADER) | A_BOLD);
        mvprintw(0, 0, "ProcHunter++ - Advanced Process Scanner");
        mvprintw(1, 0, "Credits: https://github.com/X2X0");
        mvprintw(2, 0, "========================================");
        attroff(COLOR_PAIR(COLOR_HEADER) | A_BOLD);

        // Column headers
        mvprintw(4, 0, "PID");
        mvprintw(4, 8, "Name");
        mvprintw(4, 25, "Score");
        mvprintw(4, 35, "Anomalies");
        mvprintw(4, 70, "Path");

        int row = 6;
        for (const auto& proc : processes) {
            if (row >= LINES - 2) break;

            int color = COLOR_SAFE;
            if (proc.suspicion_score >= 70) color = COLOR_CRITICAL;
            else if (proc.suspicion_score >= 40) color = COLOR_SUSPICIOUS;

            attron(COLOR_PAIR(color));
            mvprintw(row, 0, "%d", proc.pid);
            mvprintw(row, 8, "%.15s", proc.name.c_str());
            mvprintw(row, 25, "%d", proc.suspicion_score);
            
            std::string anomalies_str;
            for (const auto& anomaly : proc.anomalies) {
                anomalies_str += anomaly + "; ";
            }
            mvprintw(row, 35, "%.30s", anomalies_str.c_str());
            mvprintw(row, 70, "%.30s", proc.exe_path.c_str());
            attroff(COLOR_PAIR(color));

            row++;
        }

        // Footer
        mvprintw(LINES - 2, 0, "Press 'q' to quit, 'r' to refresh, 'k' to kill suspicious processes");
        refresh();
    }

    void runTUI() {
        initializeTUI();
        
        int ch;
        while ((ch = getch()) != 'q') {
            switch (ch) {
                case 'r':
                    scanProcesses();
                    displayTUI();
                    break;
                case 'k':
                    killSuspiciousProcesses();
                    scanProcesses();
                    displayTUI();
                    break;
                case ERR:
                    // Timeout, refresh automatically
                    scanProcesses();
                    displayTUI();
                    break;
            }
        }
        
        endwin();
    }

    void killSuspiciousProcesses() {
        for (const auto& proc : processes) {
            if (proc.suspicion_score >= detection_threshold) {
                if (!silent_mode) {
                    std::cout << "Killing suspicious process: " << proc.name 
                              << " (PID: " << proc.pid << ", Score: " 
                              << proc.suspicion_score << ")" << std::endl;
                }
                kill(proc.pid, SIGTERM);
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                kill(proc.pid, SIGKILL);
            }
        }
    }

    void exportToJSON() {
        Json::Value root;
        Json::Value processes_array(Json::arrayValue);

        for (const auto& proc : processes) {
            Json::Value process_obj;
            process_obj["pid"] = proc.pid;
            process_obj["name"] = proc.name;
            process_obj["cmdline"] = proc.cmdline;
            process_obj["exe_path"] = proc.exe_path;
            process_obj["sha256_hash"] = proc.sha256_hash;
            process_obj["suspicion_score"] = proc.suspicion_score;
            process_obj["is_hidden"] = proc.is_hidden;

            Json::Value anomalies_array(Json::arrayValue);
            for (const auto& anomaly : proc.anomalies) {
                anomalies_array.append(anomaly);
            }
            process_obj["anomalies"] = anomalies_array;

            processes_array.append(process_obj);
        }

        root["processes"] = processes_array;
        root["scan_time"] = std::time(nullptr);
        root["total_processes"] = static_cast<int>(processes.size());

        std::cout << root << std::endl;
    }

    void displayResults() {
        if (json_output) {
            exportToJSON();
            return;
        }

        if (silent_mode) return;

        std::cout << "\n=== SCAN RESULTS ===" << std::endl;
        std::cout << "Total processes scanned: " << processes.size() << std::endl;

        int suspicious_count = 0;
        for (const auto& proc : processes) {
            if (proc.suspicion_score >= detection_threshold) {
                suspicious_count++;
                std::cout << "\n[SUSPICIOUS] Process: " << proc.name 
                          << " (PID: " << proc.pid << ")" << std::endl;
                std::cout << "  Command: " << proc.cmdline << std::endl;
                std::cout << "  Path: " << proc.exe_path << std::endl;
                std::cout << "  Hash: " << proc.sha256_hash << std::endl;
                std::cout << "  Suspicion Score: " << proc.suspicion_score << std::endl;
                std::cout << "  Anomalies:" << std::endl;
                for (const auto& anomaly : proc.anomalies) {
                    std::cout << "    - " << anomaly << std::endl;
                }
            }
        }

        std::cout << "\nSuspicious processes found: " << suspicious_count << std::endl;
    }

    void run(int argc, char* argv[]) {
        // Parse command line arguments
        for (int i = 1; i < argc; i++) {
            std::string arg = argv[i];
            if (arg == "--silent" || arg == "-s") {
                silent_mode = true;
            } else if (arg == "--tui" || arg == "-t") {
                tui_mode = true;
            } else if (arg == "--json" || arg == "-j") {
                json_output = true;
            } else if (arg == "--kill" || arg == "-k") {
                // Kill mode will be handled after scanning
            } else if (arg == "--threshold" && i + 1 < argc) {
                detection_threshold = std::stoi(argv[++i]);
            } else if (arg == "--help" || arg == "-h") {
                printHelp();
                return;
            }
        }

        printBanner();
        
        if (!silent_mode) {
            std::cout << "Starting process scan..." << std::endl;
        }

        scanProcesses();

        if (tui_mode) {
            runTUI();
        } else {
            displayResults();
        }

        // Check if kill mode was requested
        for (int i = 1; i < argc; i++) {
            if (std::string(argv[i]) == "--kill" || std::string(argv[i]) == "-k") {
                killSuspiciousProcesses();
                break;
            }
        }
    }

    void printHelp() {
        std::cout << R"(
ProcHunter++ - Advanced Process Scanner
Usage: prochunter [OPTIONS]

OPTIONS:
  -s, --silent      Run in silent mode (no output until completion)
  -t, --tui         Run with Text User Interface (ncurses)
  -j, --json        Output results in JSON format
  -k, --kill        Kill processes with high suspicion scores
  --threshold NUM   Set suspicion threshold (default: 50)
  -h, --help        Show this help message

EXAMPLES:
  prochunter --tui                 # Run with interactive interface
  prochunter --json > report.json  # Export to JSON
  prochunter --kill --threshold 70 # Kill processes with score >= 70
  prochunter --silent --json       # Silent JSON output

Credits: https://github.com/X2X0
)" << std::endl;
    }
};

int main(int argc, char* argv[]) {
    // Check if running as root
    if (geteuid() != 0) {
        std::cerr << "Warning: ProcHunter++ should be run as root for full functionality." << std::endl;
    }

    ProcHunter hunter;
    try {
        hunter.run(argc, argv);
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
