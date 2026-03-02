#!/bin/bash

# Check if the script is run as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run this script with sudo or as root."
  exit 1
fi

echo "========================================"
echo "1. SCANNING USERS FOR CRONTAB JOBS"
echo "========================================"

# Loop through all users in /etc/passwd
for user in $(cut -f1 -d: /etc/passwd); do
  # Hide users with empty crontabs for cleaner output
  if sudo crontab -u "$user" -l 2>/dev/null | grep -q -v "^#"; then
    echo "=== $user ==="
    sudo crontab -u "$user" -l 2>/dev/null
    echo ""
  fi
done

echo ""
echo "========================================"
echo "2. CHECKING FOR REVERSE SHELLS (ESTABLISHED)"
echo "========================================"

# Grab all established connections using netstat or ss
if command -v netstat >/dev/null 2>&1; then
  CONNECTIONS=$(netstat -anp 2>/dev/null | grep ESTABLISHED)
else
  CONNECTIONS=$(ss -anp 2>/dev/null | grep ESTAB)
fi

# Define common reverse shell binaries
SUSPICIOUS_BINS="\b(bash|sh|dash|nc|ncat|netcat|python[0-9.]*|perl|php[0-9.]*|ruby|socat)\b"

# Filter the connections for those suspicious binaries
SUSPICIOUS_MATCHES=$(echo "$CONNECTIONS" | grep -iE "$SUSPICIOUS_BINS")

if [ -n "$SUSPICIOUS_MATCHES" ]; then
  echo "⚠️  WARNING: POTENTIAL REVERSE SHELLS DETECTED ⚠️"
  echo "The following connections belong to common shell/scripting binaries:"
  echo "--------------------------------------------------------------------"
  echo "$SUSPICIOUS_MATCHES"
  echo "--------------------------------------------------------------------"
else
  echo "✅ No obvious reverse shell processes (e.g., bash, nc, python) found."
fi

echo ""
echo "--- All Established Connections (For Manual Review) ---"
echo "$CONNECTIONS"

echo ""
echo "========================================"
echo "3. CHECKING LISTENING PORTS (OPEN SERVICES)"
echo "========================================"

# Check for open TCP/UDP ports using netstat or ss
if command -v netstat >/dev/null 2>&1; then
  netstat -tuln
else
  ss -tuln
fi

echo ""
echo "========================================"
echo "4. CHECKING FOR SUID BINARIES"
echo "   (Potential Privilege Escalation Backdoors)"
echo "========================================"
echo "Scanning filesystem... (this may take a moment)"

# Find all files with the SUID bit (-4000) set and list them
find / -type f -perm -04000 -exec ls -l {} \; 2>/dev/null

echo ""
echo "========================================"
echo "Scan complete."
