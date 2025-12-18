#! /bin/bash
set -e

# Cleanup function to handle script termination
# This function will be called on script exit or interruption
cleanup() {
    pkill -P $$  # Kill all the child processes of the current process group
    # Optional: Delete temporary files
    [ -f "$TMP_FILE" ] && rm "$TMP_FILE"
    exit 1
}

# Register Signal Capture
trap 'cleanup' INT TERM EXIT

printf "[ProType] [Size] [Metric] [Dim] [Delta] [Time(s)] [Com.(MB)]\n"

./build/main -p 1 -n 8 12 -d 2 6 10 15 -m 0 -delta 10 60 250 -trait 10 -log 0 -fm_old

./build/main -p 1 -n 8 12 -d 2 6 10 15 -m 0 -delta 10 60 250 -trait 10 -log 0