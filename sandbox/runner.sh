#!/bin/bash
# PhishGuard sandbox runner — executed inside Docker container
# Usage: bash /runner.sh <filename>

FILE="/samples/$1"
EXT="${1##*.}"

if [ ! -f "$FILE" ]; then
  echo "ERROR: File not found: $FILE"
  exit 1
fi

# Start network capture
tcpdump -i any -w /tmp/net.pcap 2>/dev/null &
TCPDUMP_PID=$!

# Execute based on file type, wrapped in strace
case "$EXT" in
  pdf)
    strace -o /tmp/syscalls.log -f \
      python3 -c "
import subprocess, sys
subprocess.run(['pdftotext', '/samples/$1', '/tmp/out.txt'], timeout=20)
" 2>&1 ;;
  doc|docx)
    strace -o /tmp/syscalls.log -f \
      libreoffice --headless --convert-to txt "$FILE" --outdir /tmp/ 2>&1 ;;
  exe)
    strace -o /tmp/syscalls.log -f \
      wine "$FILE" 2>&1 ;;
  py)
    strace -o /tmp/syscalls.log -f \
      python3 "$FILE" 2>&1 ;;
  *)
    strace -o /tmp/syscalls.log -f \
      python3 -c "print('Unsupported type: $EXT')" 2>&1 ;;
esac

sleep 1
kill $TCPDUMP_PID 2>/dev/null

echo "=== SYSCALLS ==="
cat /tmp/syscalls.log 2>/dev/null | head -500

echo "=== NETWORK ==="
tcpdump -r /tmp/net.pcap -n 2>/dev/null | head -100
