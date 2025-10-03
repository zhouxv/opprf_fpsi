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


log "Running benchmarks for FuzzyPSI protocol..."
printf "[ProType] [Metric] [Dim] [Delta] [Size] [Com.(MB)] [Time(s)]\n"

./main -n 8 -d 2 6 10 -delta 10 30 60 120 250 -trait 10 -comp_idx 1 -log 0

printf "######################################################\n"

./main -n 12 -d 2 6 10 -delta 10 30 60 120 250 -trait 10 -comp_idx 1 -log 0

printf "######################################################\n"

./main -n 16 -d 2 6 10 -delta 10 30 60 120 250 -trait 10 -comp_idx 1 -log 0
