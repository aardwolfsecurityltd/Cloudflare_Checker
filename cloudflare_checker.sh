#!/bin/bash

# Cloudflare IP Range Checker
# This script checks if a given IP address is within Cloudflare's IP ranges

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Cloudflare IP list URLs
CF_IPV4_URL="https://www.cloudflare.com/ips-v4"
CF_IPV6_URL="https://www.cloudflare.com/ips-v6"

# Temporary files
TEMP_DIR=$(mktemp -d)
IPV4_LIST="${TEMP_DIR}/cf_ipv4.txt"
IPV6_LIST="${TEMP_DIR}/cf_ipv6.txt"

# Cleanup function
cleanup() {
    rm -rf "$TEMP_DIR"
}
trap cleanup EXIT

# Function to display usage
usage() {
    echo "Usage: $0 <IP_ADDRESS> [IP_ADDRESS2 ...]"
    echo "       $0 -f <FILE_PATH>"
    echo ""
    echo "Examples:"
    echo "  Single IP:     $0 104.16.1.1"
    echo "  Multiple IPs:  $0 104.16.1.1 2606:4700::1 8.8.8.8"
    echo "  From file:     $0 -f ip_list.txt"
    echo ""
    echo "File format: One IP address per line"
    exit 1
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to download Cloudflare IP lists
download_cf_ips() {
    echo -e "${YELLOW}Downloading Cloudflare IP ranges...${NC}"
    
    if command_exists curl; then
        curl -s "$CF_IPV4_URL" > "$IPV4_LIST" || {
            echo -e "${RED}Error: Failed to download IPv4 list${NC}" >&2
            exit 1
        }
        curl -s "$CF_IPV6_URL" > "$IPV6_LIST" || {
            echo -e "${RED}Error: Failed to download IPv6 list${NC}" >&2
            exit 1
        }
    elif command_exists wget; then
        wget -q -O "$IPV4_LIST" "$CF_IPV4_URL" || {
            echo -e "${RED}Error: Failed to download IPv4 list${NC}" >&2
            exit 1
        }
        wget -q -O "$IPV6_LIST" "$CF_IPV6_URL" || {
            echo -e "${RED}Error: Failed to download IPv6 list${NC}" >&2
            exit 1
        }
    else
        echo -e "${RED}Error: Neither curl nor wget found. Please install one of them.${NC}" >&2
        exit 1
    fi
    
    echo -e "${GREEN}Downloaded Cloudflare IP ranges successfully${NC}"
}

# Function to validate IP address format
validate_ip() {
    local ip="$1"
    
    # Check if it's IPv4
    if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        # Validate each octet is between 0-255
        IFS='.' read -ra ADDR <<< "$ip"
        for i in "${ADDR[@]}"; do
            # Remove leading zeros and check range
            local num=$((10#$i))
            if [[ $num -lt 0 || $num -gt 255 ]]; then
                return 1
            fi
        done
        echo "ipv4"
        return 0
    fi
    
    # Check if it's IPv6 (basic validation)
    if [[ "$ip" =~ ^[0-9a-fA-F:]+$ ]] && [[ "$ip" == *":"* ]]; then
        echo "ipv6"
        return 0
    fi
    
    return 1
}

# Function to convert IP to decimal (IPv4 only)
ip_to_decimal() {
    local ip="$1"
    local a b c d
    IFS='.' read -r a b c d <<< "$ip"
    echo $((a * 256**3 + b * 256**2 + c * 256 + d))
}

# Function to check if IPv4 is in CIDR range
ip_in_cidr_v4() {
    local ip="$1"
    local cidr="$2"
    
    local network mask
    IFS='/' read -r network mask <<< "$cidr"
    
    local ip_dec network_dec
    ip_dec=$(ip_to_decimal "$ip")
    network_dec=$(ip_to_decimal "$network")
    
    local mask_dec=$((0xFFFFFFFF << (32 - mask) & 0xFFFFFFFF))
    
    [[ $((ip_dec & mask_dec)) -eq $((network_dec & mask_dec)) ]]
}

# Function to check IPv6 using system tools
check_ipv6_in_range() {
    local ip="$1"
    local cidr="$2"
    
    # Use Python if available for IPv6 calculations
    if command_exists python3; then
        python3 -c "
import ipaddress
try:
    ip = ipaddress.ip_address('$ip')
    network = ipaddress.ip_network('$cidr', strict=False)
    exit(0 if ip in network else 1)
except:
    exit(1)
" 2>/dev/null
        return $?
    fi
    
    # Fallback: use ipcalc if available
    if command_exists ipcalc; then
        ipcalc -c "$ip" "$cidr" >/dev/null 2>&1
        return $?
    fi
    
    # If no tools available, skip IPv6 check
    echo -e "${YELLOW}Warning: Cannot verify IPv6 ranges (missing python3 or ipcalc)${NC}" >&2
    return 1
}

# Main function to check IP against Cloudflare ranges
check_ip() {
    local target_ip="$1"
    local ip_type
    local quiet="${2:-}"  # Optional quiet mode for batch processing
    
    # Validate IP format
    if ! ip_type=$(validate_ip "$target_ip"); then
        if [[ "$quiet" != "quiet" ]]; then
            echo -e "${RED}Error: Invalid IP address format: $target_ip${NC}" >&2
        fi
        return 1
    fi
    
    if [[ "$quiet" != "quiet" ]]; then
        echo "Checking IP: $target_ip (${ip_type})"
        echo "----------------------------------------"
    fi
    
    local found=false
    local ip_list
    local matched_cidr=""
    
    if [[ "$ip_type" == "ipv4" ]]; then
        ip_list="$IPV4_LIST"
        if [[ "$quiet" != "quiet" ]]; then
            echo "Checking against IPv4 ranges..."
        fi
        
        while IFS= read -r cidr; do
            [[ -z "$cidr" ]] && continue
            if ip_in_cidr_v4 "$target_ip" "$cidr"; then
                matched_cidr="$cidr"
                found=true
                break
            fi
        done < "$ip_list"
        
    elif [[ "$ip_type" == "ipv6" ]]; then
        ip_list="$IPV6_LIST"
        if [[ "$quiet" != "quiet" ]]; then
            echo "Checking against IPv6 ranges..."
        fi
        
        while IFS= read -r cidr; do
            [[ -z "$cidr" ]] && continue
            if check_ipv6_in_range "$target_ip" "$cidr"; then
                matched_cidr="$cidr"
                found=true
                break
            fi
        done < "$ip_list"
    fi
    
    if [[ "$found" == true ]]; then
        if [[ "$quiet" == "quiet" ]]; then
            echo -e "${GREEN}✓ $target_ip${NC} -> $matched_cidr"
        else
            echo -e "${GREEN}✓ IP $target_ip is within Cloudflare range: $matched_cidr${NC}"
        fi
        return 0
    else
        if [[ "$quiet" == "quiet" ]]; then
            echo -e "${RED}✗ $target_ip${NC} -> Not in Cloudflare ranges"
        else
            echo -e "${RED}✗ IP $target_ip is NOT within any Cloudflare range${NC}"
        fi
        return 1
    fi
}

# Function to read IPs from file
read_ips_from_file() {
    local file_path="$1"
    
    if [[ ! -f "$file_path" ]]; then
        echo -e "${RED}Error: File not found: $file_path${NC}" >&2
        exit 1
    fi
    
    if [[ ! -r "$file_path" ]]; then
        echo -e "${RED}Error: Cannot read file: $file_path${NC}" >&2
        exit 1
    fi
    
    # Read file and filter out empty lines and comments
    grep -v '^\s*#' "$file_path" | grep -v '^\s*$' | tr -d '\r'
}

# Function to process multiple IPs
process_multiple_ips() {
    local ip_list=("$@")
    local total=${#ip_list[@]}
    local cloudflare_count=0
    local non_cloudflare_count=0
    local invalid_count=0
    
    echo -e "${YELLOW}Processing $total IP addresses...${NC}"
    echo "========================================"
    echo ""
    
    for ip in "${ip_list[@]}"; do
        # Skip empty lines
        [[ -z "$ip" ]] && continue
        
        if check_ip "$ip" "quiet"; then
            ((cloudflare_count++))
        else
            # Check if it was invalid format vs not in range
            if ! validate_ip "$ip" >/dev/null 2>&1; then
                ((invalid_count++))
            else
                ((non_cloudflare_count++))
            fi
        fi
    done
    
    echo ""
    echo "========================================"
    echo -e "${YELLOW}Summary:${NC}"
    echo -e "  Total IPs processed: $total"
    echo -e "  ${GREEN}Cloudflare IPs: $cloudflare_count${NC}"
    echo -e "  ${RED}Non-Cloudflare IPs: $non_cloudflare_count${NC}"
    if [[ $invalid_count -gt 0 ]]; then
        echo -e "  ${YELLOW}Invalid IPs: $invalid_count${NC}"
    fi
    
    # Return appropriate exit code
    if [[ $invalid_count -gt 0 ]]; then
        return 2  # Some invalid IPs
    elif [[ $non_cloudflare_count -gt 0 ]]; then
        return 1  # Some non-Cloudflare IPs
    else
        return 0  # All are Cloudflare IPs
    fi
}

# Main execution
main() {
    # Check arguments
    if [[ $# -eq 0 ]]; then
        usage
    fi
    
    # Download Cloudflare IP ranges
    download_cf_ips
    
    # Check if reading from file
    if [[ "$1" == "-f" ]]; then
        if [[ $# -ne 2 ]]; then
            echo -e "${RED}Error: -f option requires a file path${NC}" >&2
            usage
        fi
        
        local file_path="$2"
        echo -e "${YELLOW}Reading IP addresses from file: $file_path${NC}"
        
        # Read IPs from file into array
        local ip_array=()
        while IFS= read -r line; do
            ip_array+=("$line")
        done < <(read_ips_from_file "$file_path")
        
        if [[ ${#ip_array[@]} -eq 0 ]]; then
            echo -e "${RED}Error: No valid IP addresses found in file${NC}" >&2
            exit 1
        fi
        
        # Process multiple IPs
        if process_multiple_ips "${ip_array[@]}"; then
            echo -e "${GREEN}All IP addresses are within Cloudflare ranges${NC}"
        else
            exit_code=$?
            if [[ $exit_code -eq 2 ]]; then
                echo -e "${YELLOW}Some IP addresses had invalid format${NC}"
            fi
            exit $exit_code
        fi
        
    elif [[ $# -eq 1 ]]; then
        # Single IP mode
        local target_ip="$1"
        check_ip "$target_ip"
        echo -e "${GREEN}Check completed successfully${NC}"
        
    else
        # Multiple IP arguments mode
        echo -e "${YELLOW}Processing ${#@} IP addresses...${NC}"
        
        # Process multiple IPs
        if process_multiple_ips "$@"; then
            echo -e "${GREEN}All IP addresses are within Cloudflare ranges${NC}"
        else
            exit_code=$?
            if [[ $exit_code -eq 2 ]]; then
                echo -e "${YELLOW}Some IP addresses had invalid format${NC}"
            fi
            exit $exit_code
        fi
    fi
}

# Run main function with all arguments
main "$@"
