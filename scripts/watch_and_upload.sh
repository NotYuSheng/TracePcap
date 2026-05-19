#!/usr/bin/env bash
# watch_and_upload.sh — watch a directory and automatically upload new PCAPs
#                       to TracePcap, adding each as a Monitor network snapshot.
#
# Requires: curl, jq
# Optional: inotify-tools (for event-driven watching on Linux; falls back to polling)
#
# Usage:
#   chmod +x watch_and_upload.sh
#   ./watch_and_upload.sh <watch_dir> <networkId> [base_url]
#
# Example:
#   ./watch_and_upload.sh /var/log/pcaps abc-123-def http://192.168.1.10:8888
#
# Finding your networkId:
#   Open TracePcap → Monitor tab → click your network →
#   copy the UUID from the URL: /monitor/<networkId>

set -euo pipefail

WATCH_DIR="${1:?Usage: $0 <watch_dir> <networkId> [base_url]}"
NETWORK_ID="${2:?Usage: $0 <watch_dir> <networkId> [base_url]}"
BASE_URL="${3:-http://localhost:8888}"
POLL_INTERVAL=30   # seconds between scans when inotifywait is unavailable
SEEN_FILE="/tmp/.tracepcap_seen_$$"
touch "$SEEN_FILE"

upload_and_add() {
  local filepath="$1"
  local filename
  filename=$(basename "$filepath")

  echo "[+] Uploading $filename..."
  local response
  response=$(curl -sf -X POST "$BASE_URL/api/files" \
    -F "file=@$filepath" \
    -F "enableNdpi=true" \
    -F "enableFileExtraction=true") || { echo "[-] Upload request failed for $filename"; return 1; }

  local file_id
  file_id=$(echo "$response" | jq -r '.id')
  if [[ -z "$file_id" || "$file_id" == "null" ]]; then
    echo "[-] Upload failed for $filename — response: $response"
    return 1
  fi
  echo "    fileId: $file_id"

  # Poll until analysis completes (up to 10 minutes)
  local status="PENDING"
  local attempts=0
  while [[ "$status" != "COMPLETED" && "$status" != "FAILED" && $attempts -lt 120 ]]; do
    sleep 5
    status=$(curl -sf "$BASE_URL/api/files/$file_id" | jq -r '.status')
    echo "    status: $status"
    ((attempts++))
  done

  if [[ "$status" != "COMPLETED" ]]; then
    echo "[-] Analysis did not complete for $filename (status: $status)"
    return 1
  fi

  # Add as snapshot to the Monitor network
  curl -sf -X POST "$BASE_URL/api/monitor/networks/$NETWORK_ID/snapshots" \
    -H "Content-Type: application/json" \
    -d "{\"fileId\":\"$file_id\"}" > /dev/null
  echo "[✓] Added $filename as snapshot to network $NETWORK_ID"
}

# Seed seen list with files already present — skip them on first run
while IFS= read -r -d '' f; do
  echo "$f" >> "$SEEN_FILE"
done < <(find "$WATCH_DIR" -maxdepth 1 \( -name "*.pcap" -o -name "*.pcapng" -o -name "*.cap" \) -print0 2>/dev/null)

echo "[*] Watching $WATCH_DIR for new PCAP files (target: $BASE_URL, network: $NETWORK_ID)..."

if command -v inotifywait &>/dev/null; then
  # Event-driven — reacts immediately when a file is fully written
  inotifywait -m -e close_write,moved_to --format '%w%f' "$WATCH_DIR" | while read -r filepath; do
    case "$filepath" in *.pcap|*.pcapng|*.cap) ;; *) continue ;; esac
    grep -qxF "$filepath" "$SEEN_FILE" && continue
    echo "$filepath" >> "$SEEN_FILE"
    upload_and_add "$filepath" || true
  done
else
  # Polling fallback
  echo "[!] inotifywait not found — falling back to polling every ${POLL_INTERVAL}s"
  echo "    Install inotify-tools for event-driven watching: apt install inotify-tools"
  while true; do
    while IFS= read -r -d '' filepath; do
      grep -qxF "$filepath" "$SEEN_FILE" && continue
      echo "$filepath" >> "$SEEN_FILE"
      upload_and_add "$filepath" || true
    done < <(find "$WATCH_DIR" -maxdepth 1 \( -name "*.pcap" -o -name "*.pcapng" -o -name "*.cap" \) -print0 2>/dev/null)
    sleep "$POLL_INTERVAL"
  done
fi
