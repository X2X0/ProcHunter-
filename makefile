# Makefile for ProcHunter++
# Credits: https://github.com/X2X0

CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2 -march=native
LDFLAGS = -lssl -lcrypto -lncurses -ljsoncpp -lpthread -static-libgcc -static-libstdc++

# Directories
SRCDIR = src
BUILDDIR = build
BINDIR = bin

# Source files
SOURCES = prochunter.cpp
OBJECTS = $(SOURCES:%.cpp=$(BUILDDIR)/%.o)
TARGET = $(BINDIR)/prochunter

# Default target
all: directories $(TARGET)

# Create necessary directories
directories:
	@mkdir -p $(BUILDDIR) $(BINDIR)

# Build the main executable
$(TARGET): $(OBJECTS)
	$(CXX) $(OBJECTS) -o $@ $(LDFLAGS)
	@echo "ProcHunter++ compiled successfully!"

# Compile source files
$(BUILDDIR)/%.o: $(SRCDIR)/%.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Static build for forensic environments
static: LDFLAGS += -static
static: directories $(TARGET)
	@echo "Static build completed - suitable for LiveCDs and forensic environments"

# Debug build
debug: CXXFLAGS += -g -DDEBUG -O0
debug: directories $(TARGET)
	@echo "Debug build completed"

# Install system-wide
install: $(TARGET)
	@sudo cp $(TARGET) /usr/local/bin/
	@sudo chmod +x /usr/local/bin/prochunter
	@echo "ProcHunter++ installed to /usr/local/bin/"

# Create package
package: static
	@mkdir -p package/prochunter++
	@cp $(TARGET) package/prochunter++/
	@cp README.md package/prochunter++/
	@cp whitelist.txt package/prochunter++/
	@tar -czf prochunter++.tar.gz -C package prochunter++
	@echo "Package created: prochunter++.tar.gz"

# Clean build files
clean:
	rm -rf $(BUILDDIR) $(BINDIR) package prochunter++.tar.gz

# Clean and rebuild
rebuild: clean all

# Check dependencies
deps-check:
	@echo "Checking dependencies..."
	@pkg-config --exists openssl || echo "ERROR: OpenSSL development libraries not found"
	@pkg-config --exists ncurses || echo "ERROR: ncurses development libraries not found"
	@pkg-config --exists jsoncpp || echo "ERROR: jsoncpp development libraries not found"
	@echo "Dependency check completed"

# Install dependencies (Ubuntu/Debian)
deps-install-ubuntu:
	sudo apt-get update
	sudo apt-get install -y build-essential libssl-dev libncurses5-dev libjsoncpp-dev

# Install dependencies (RHEL/CentOS/Fedora)
deps-install-rhel:
	sudo yum install -y gcc-c++ openssl-devel ncurses-devel jsoncpp-devel

# Run tests
test: $(TARGET)
	@echo "Running basic functionality tests..."
	@$(TARGET) --help > /dev/null && echo "✓ Help command works"
	@timeout 5s $(TARGET) --silent --json > /dev/null && echo "✓ Silent JSON mode works"
	@echo "Basic tests completed"

# Security scan with checksec
security-check: $(TARGET)
	@command -v checksec >/dev/null 2>&1 && checksec --file=$(TARGET) || echo "Install checksec for security analysis"

# Benchmark
benchmark: $(TARGET)
	@echo "Running performance benchmark..."
	@time $(TARGET) --silent > /dev/null

# Help
help:
	@echo "ProcHunter++ Build System"
	@echo "Credits: https://github.com/X2X0"
	@echo ""
	@echo "Available targets:"
	@echo "  all              - Build ProcHunter++ (default)"
	@echo "  static           - Build static binary for forensic use"
	@echo "  debug            - Build with debug symbols"
	@echo "  install          - Install to /usr/local/bin"
	@echo "  package          - Create distribution package"
	@echo "  clean            - Clean build files"
	@echo "  rebuild          - Clean and rebuild"
	@echo "  deps-check       - Check for required dependencies"
	@echo "  deps-install-*   - Install dependencies for various distros"
	@echo "  test             - Run basic functionality tests"
	@echo "  security-check   - Run security analysis"
	@echo "  benchmark        - Performance benchmark"
	@echo "  help             - Show this help"

.PHONY: all static debug install package clean rebuild deps-check deps-install-ubuntu deps-install-rhel test security-check benchmark help directories

# Configuration for different architectures
ifeq ($(shell uname -m),x86_64)
    CXXFLAGS += -m64
else ifeq ($(shell uname -m),i686)
    CXXFLAGS += -m32
endif

# Optimization for different build types
ifeq ($(MAKECMDGOALS),debug)
    CXXFLAGS := $(filter-out -O2 -march=native,$(CXXFLAGS))
endif
