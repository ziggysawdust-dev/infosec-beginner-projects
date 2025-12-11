#!/bin/bash
# Simple log viewer - displays real system logs in human-readable format

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

show_help() {
    echo "Human-readable log viewer"
    echo ""
    echo "Usage: ./view_logs.sh [command] [options] [--wtmp /path/to/wtmp]"
    echo ""
    echo "Commands:"
    echo "  auth              View SSH/auth logs (last 50 lines)"
    echo "  auth [N]          View last N lines of auth logs"
    echo "  syslog            View system logs (last 50 lines)"
    echo "  syslog [N]        View last N lines of syslog"
    echo "  wtmp              View login/logout history from /var/log/wtmp"
    echo "  sudo              View sudo command execution"
    echo "  apache            View Apache web server logs"
    echo "  fail              View failed login attempts"
    echo "  success           View successful logins"
    echo "  user [USERNAME]   View logs for specific user"
    echo "  ip [IP]           View logs from specific IP"
    echo ""
    echo "Global Options:"
    echo "  --wtmp /path      Point to custom wtmp file location"
    echo ""
    echo "Examples:"
    echo "  ./view_logs.sh auth                      # Last 50 auth log lines"
    echo "  ./view_logs.sh auth 100                  # Last 100 auth log lines"
    echo "  ./view_logs.sh user root                 # All logs for user 'root'"
    echo "  ./view_logs.sh ip 192.168                # Logs from IPs starting with 192.168"
    echo "  ./view_logs.sh wtmp --wtmp ./htb-wtmp   # Custom wtmp file in current directory"
    echo ""
}

print_header() {
    echo ""
    echo -e "${BOLD}${BLUE}═══════════════════════════════════════${RESET}"
    echo -e "${BOLD}${BLUE}$1${RESET}"
    echo -e "${BOLD}${BLUE}═══════════════════════════════════════${RESET}"
    echo ""
}

check_file() {
    if [[ ! -f "$1" ]]; then
        echo -e "${RED}Error: $1 not found${RESET}"
        echo "This script needs to be run on a Linux system with standard log files."
        return 1
    fi
    return 0
}

view_auth_logs() {
    local lines=${1:-50}
    print_header "AUTHENTICATION LOGS (last $lines lines)"
    
    if check_file "/var/log/auth.log"; then
        tail -n $lines /var/log/auth.log | while read -r line; do
            if [[ "$line" =~ "Accepted" ]]; then
                echo -e "${GREEN}✓${RESET} $line"
            elif [[ "$line" =~ "Failed" ]] || [[ "$line" =~ "Invalid" ]]; then
                echo -e "${RED}✗${RESET} $line"
            elif [[ "$line" =~ "sudo" ]]; then
                echo -e "${YELLOW}⚡${RESET} $line"
            else
                echo -e "${CYAN}•${RESET} $line"
            fi
        done
    fi
}

view_syslog() {
    local lines=${1:-50}
    print_header "SYSTEM LOG (last $lines lines)"
    
    if check_file "/var/log/syslog"; then
        tail -n $lines /var/log/syslog | while read -r line; do
            if [[ "$line" =~ "error" ]] || [[ "$line" =~ "Error" ]]; then
                echo -e "${RED}$line${RESET}"
            elif [[ "$line" =~ "warn" ]] || [[ "$line" =~ "Warn" ]]; then
                echo -e "${YELLOW}$line${RESET}"
            else
                echo "$line"
            fi
        done
    fi
}

view_wtmp() {
    local wtmp_file="${CUSTOM_WTMP:-/var/log/wtmp}"
    print_header "LOGIN/LOGOUT HISTORY (from $wtmp_file)"
    
    if check_file "$wtmp_file"; then
        # Use last command to show login history from specific file
        last -f "$wtmp_file" | head -50 | while read -r line; do
            if [[ "$line" =~ "still logged in" ]]; then
                echo -e "${GREEN}$line${RESET}"
            elif [[ "$line" =~ "shutdown" ]] || [[ "$line" =~ "reboot" ]]; then
                echo -e "${YELLOW}$line${RESET}"
            else
                echo "$line"
            fi
        done
    fi
}

view_sudo() {
    print_header "SUDO COMMAND EXECUTION"
    
    if check_file "/var/log/auth.log"; then
        grep -i sudo /var/log/auth.log | tail -50 | while read -r line; do
            echo -e "${YELLOW}⚡${RESET} $line"
        done
    fi
}

view_apache() {
    print_header "APACHE WEB SERVER LOGS"
    
    local access_log="/var/log/apache2/access.log"
    if [[ ! -f "$access_log" ]]; then
        access_log="/var/log/httpd/access_log"
    fi
    
    if check_file "$access_log"; then
        tail -50 "$access_log" | while read -r line; do
            if [[ "$line" =~ "200 " ]]; then
                echo -e "${GREEN}✓${RESET} $line"
            elif [[ "$line" =~ "404 " ]] || [[ "$line" =~ "403 " ]]; then
                echo -e "${RED}✗${RESET} $line"
            elif [[ "$line" =~ "500 " ]]; then
                echo -e "${RED}⚠${RESET} $line"
            else
                echo "$line"
            fi
        done
    fi
}

view_failed_logins() {
    print_header "FAILED LOGIN ATTEMPTS"
    
    if check_file "/var/log/auth.log"; then
        grep -i "failed\|invalid" /var/log/auth.log | tail -50 | while read -r line; do
            echo -e "${RED}$line${RESET}"
        done
    fi
}

view_successful_logins() {
    print_header "SUCCESSFUL LOGINS"
    
    if check_file "/var/log/auth.log"; then
        grep -i "accepted" /var/log/auth.log | tail -50 | while read -r line; do
            echo -e "${GREEN}$line${RESET}"
        done
    fi
}

view_by_user() {
    local user=$1
    print_header "LOGS FOR USER: $user"
    
    if check_file "/var/log/auth.log"; then
        grep " $user " /var/log/auth.log | tail -50 | while read -r line; do
            if [[ "$line" =~ "Accepted" ]]; then
                echo -e "${GREEN}✓${RESET} $line"
            elif [[ "$line" =~ "Failed\|Invalid" ]]; then
                echo -e "${RED}✗${RESET} $line"
            else
                echo "$line"
            fi
        done
    fi
}

view_by_ip() {
    local ip=$1
    print_header "LOGS FROM IP: $ip"
    
    if check_file "/var/log/auth.log"; then
        grep "$ip" /var/log/auth.log | tail -50 | while read -r line; do
            if [[ "$line" =~ "Accepted" ]]; then
                echo -e "${GREEN}✓${RESET} $line"
            elif [[ "$line" =~ "Failed\|Invalid" ]]; then
                echo -e "${RED}✗${RESET} $line"
            else
                echo "$line"
            fi
        done
    fi
}

# Main logic
if [[ $# -eq 0 ]]; then
    show_help
    exit 0
fi

# Parse global options first
CUSTOM_WTMP=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --wtmp)
            CUSTOM_WTMP="$2"
            shift 2
            ;;
        *)
            break
            ;;
    esac
done

case "$1" in
    auth)
        view_auth_logs "${2:-50}"
        ;;
    syslog)
        view_syslog "${2:-50}"
        ;;
    wtmp)
        view_wtmp
        ;;
    sudo)
        view_sudo
        ;;
    apache)
        view_apache
        ;;
    fail|failed)
        view_failed_logins
        ;;
    success|successful)
        view_successful_logins
        ;;
    user)
        if [[ -z "$2" ]]; then
            echo "Usage: ./view_logs.sh user [username]"
            exit 1
        fi
        view_by_user "$2"
        ;;
    ip)
        if [[ -z "$2" ]]; then
            echo "Usage: ./view_logs.sh ip [ip_address]"
            exit 1
        fi
        view_by_ip "$2"
        ;;
    help|-h|--help)
        show_help
        ;;
    *)
        echo "Unknown command: $1"
        show_help
        exit 1
        ;;
esac
