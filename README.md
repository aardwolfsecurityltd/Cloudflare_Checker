# Cloudflare IP Checker

A bash script that checks if IP addresses are within Cloudflare's official IP ranges. Perfect for security audits, log analysis, and identifying Cloudflare-proxied services.

## Features

- ✅ **Single IP checking** - Verify individual IP addresses
- ✅ **Batch processing** - Check multiple IPs from command line or file
- ✅ **IPv4 and IPv6 support** - Handles both IP versions
- ✅ **Real-time data** - Downloads latest IP ranges from Cloudflare
- ✅ **Multiple input methods** - Command line arguments or file input
- ✅ **Detailed reporting** - Summary statistics and colored output
- ✅ **Error handling** - Validates IP formats and handles edge cases

## Installation

1. Download the script:
```bash
wget https://raw.githubusercontent.com/aardwolfsecurityltd/cloudflare-ip-checker/main/cloudflare_checker.sh
# or
curl -O https://raw.githubusercontent.com/aardwolfsecurityltd/cloudflare-ip-checker/main/cloudflare_checker.sh
```

2. Make it executable:
```bash
chmod +x cloudflare_checker.sh
```

## Requirements

- **bash** (version 4.0+)
- **curl** or **wget** for downloading IP ranges
- **python3** or **ipcalc** (optional, for IPv6 support)

## Usage

### Single IP Address
```bash
./cloudflare_checker.sh 104.16.1.1
```

### Multiple IP Addresses
```bash
./cloudflare_checker.sh 104.16.1.1 8.8.8.8 2606:4700::1
```

### From File
```bash
./cloudflare_checker.sh -f ip_list.txt
```

### File Format
Create a text file with one IP address per line:
```
# Cloudflare test IPs
104.16.1.1
2606:4700::1

# Other services (comments are ignored)
8.8.8.8
1.1.1.1
```

## Output Examples

### Single IP Check
```
Downloading Cloudflare IP ranges...
Downloaded Cloudflare IP ranges successfully
Checking IP: 104.16.1.1 (ipv4)
----------------------------------------
Checking against IPv4 ranges...
✓ IP 104.16.1.1 is within Cloudflare range: 104.16.0.0/13
Check completed successfully
```

### Batch Processing
```
Processing 5 IP addresses...
========================================

✓ 104.16.1.1 -> 104.16.0.0/13
✓ 2606:4700::1 -> 2606:4700::/32
✗ 8.8.8.8 -> Not in Cloudflare ranges
✗ 1.1.1.1 -> Not in Cloudflare ranges
✓ 162.158.1.1 -> 162.158.0.0/15

========================================
Summary:
  Total IPs processed: 5
  Cloudflare IPs: 3
  Non-Cloudflare IPs: 2
```

## Exit Codes

The script returns different exit codes for automation:

- **0**: All IPs are within Cloudflare ranges
- **1**: Some IPs are not in Cloudflare ranges
- **2**: Some IPs had invalid format

## Use Cases

### Security Analysis
```bash
# Check if suspicious IPs are behind Cloudflare
./cloudflare_checker.sh 185.199.108.153 104.16.123.96
```

### Log Processing
```bash
# Extract IPs from web server logs and check them
grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' access.log | sort -u > ips.txt
./cloudflare_checker.sh -f ips.txt
```

### CI/CD Integration
```bash
#!/bin/bash
if ./cloudflare_checker.sh -f production_ips.txt; then
    echo "All production IPs are properly behind Cloudflare"
else
    echo "Warning: Some IPs are not using Cloudflare protection"
    exit 1
fi
```

### Network Monitoring
```bash
# Check a list of your domains' IPs
dig +short example.com | ./cloudflare_checker.sh -f -
```

## Advanced Usage

### Combining with Other Tools
```bash
# Check IPs from nmap scan
nmap -sn 192.168.1.0/24 | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | \
./cloudflare_checker.sh -f -

# Check IPs from DNS resolution
dig +short @8.8.8.8 example.com | ./cloudflare_checker.sh -f -
```

### Automation Scripts
```bash
#!/bin/bash
# Daily Cloudflare check for critical services
CRITICAL_IPS="critical_services.txt"
if ! ./cloudflare_checker.sh -f "$CRITICAL_IPS"; then
    echo "Alert: Critical services not behind Cloudflare!" | mail admin@company.com
fi
```

## Technical Details

### How It Works
1. Downloads current IP ranges from Cloudflare's official endpoints:
   - IPv4: `https://www.cloudflare.com/ips-v4`
   - IPv6: `https://www.cloudflare.com/ips-v6`
2. Validates input IP address format
3. Performs CIDR range matching against downloaded ranges
4. Reports results with detailed output

### IPv6 Support
For IPv6 addresses, the script uses:
- **Python3** `ipaddress` module (preferred)
- **ipcalc** utility (fallback)
- Manual validation (basic check only)

**⭐ Star this repository if you find it useful!**
