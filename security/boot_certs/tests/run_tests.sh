#!/bin/bash
# Boot Certificate Test Suite Runner
#
# Usage:
#   ./run_tests.sh                    # Run unit tests only
#   ./run_tests.sh --all              # Run all tests (requires root + module loaded)
#   ./run_tests.sh --kernel           # Run kernel integration tests
#   ./run_tests.sh --coverage         # Run with coverage report
#   ./run_tests.sh --watch            # Run in watch mode (requires pytest-watch)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Activate virtual environment if it exists
if [ -f "venv/bin/activate" ]; then
    source venv/bin/activate
fi

# Helper functions
error() {
    echo -e "${RED}ERROR: $1${NC}" >&2
}

info() {
    echo -e "${GREEN}INFO: $1${NC}"
}

warn() {
    echo -e "${YELLOW}WARN: $1${NC}"
}

# Check dependencies
check_dependencies() {
    if ! command -v pytest &> /dev/null; then
        error "pytest not found."
        error "Create virtual environment and install:"
        error "  python3 -m venv venv"
        error "  source venv/bin/activate"
        error "  pip install -r requirements.txt"
        exit 1
    fi
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        warn "Not running as root - kernel integration tests will be skipped"
        return 1
    fi
    return 0
}

# Check if module is loaded
check_module() {
    if ! lsmod | grep -q boot_certs_sysfs; then
        warn "boot_certs module not loaded - integration tests will be skipped"
        return 1
    fi
    return 0
}

# Run tests
run_tests() {
    local pytest_args=()

    case "${1:-unit}" in
        unit)
            info "Running unit tests only..."
            pytest_args+=("-m" "not kernel")
            ;;
        kernel)
            info "Running kernel integration tests..."
            if ! check_root; then
                error "Kernel tests require root privileges"
                exit 1
            fi
            if ! check_module; then
                error "Kernel tests require boot_certs module to be loaded"
                exit 1
            fi
            pytest_args+=("-m" "kernel")
            ;;
        all)
            info "Running all tests..."
            if ! check_root; then
                warn "Skipping kernel tests (not root)"
                pytest_args+=("-m" "not kernel")
            elif ! check_module; then
                warn "Skipping kernel tests (module not loaded)"
                pytest_args+=("-m" "not kernel")
            fi
            ;;
        coverage)
            info "Running tests with coverage..."
            pytest_args+=("--cov=." "--cov-report=html" "--cov-report=term")
            ;;
        watch)
            info "Running tests in watch mode..."
            if ! command -v ptw &> /dev/null; then
                error "pytest-watch not installed: pip3 install pytest-watch"
                exit 1
            fi
            ptw -- "${pytest_args[@]}"
            return
            ;;
        *)
            error "Unknown test mode: $1"
            echo "Usage: $0 [unit|kernel|all|coverage|watch]"
            exit 1
            ;;
    esac

    pytest "${pytest_args[@]}" test_boot_certs.py
}

# Main
main() {
    check_dependencies

    local mode="${1:-unit}"

    # Parse command line
    case "$mode" in
        --all)
            run_tests all
            ;;
        --kernel)
            run_tests kernel
            ;;
        --coverage)
            run_tests coverage
            ;;
        --watch)
            run_tests watch
            ;;
        --help|-h)
            cat <<EOF
Boot Certificate Test Suite Runner

Usage:
    $0 [OPTIONS]

Options:
    (none)          Run unit tests only (default)
    --all           Run all tests (requires root + loaded module)
    --kernel        Run kernel integration tests only
    --coverage      Run with coverage report
    --watch         Run in watch mode (requires pytest-watch)
    --help, -h      Show this help

Examples:
    $0                      # Run unit tests
    sudo $0 --all           # Run all tests as root
    $0 --coverage           # Generate coverage report

EOF
            ;;
        *)
            run_tests unit
            ;;
    esac
}

main "$@"
