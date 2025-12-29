#! /bin/bash
# set -e

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


ns=(8 12 16)
dims=(2 6 10 15)
deltas=(10 60 250)

printf "[ProType] [Size] [Metric] [Dim] [Delta] [Time(s)] [Com.(MB)]\n"

for n in "${ns[@]}"; do
  for dim in "${dims[@]}"; do
    for delta in "${deltas[@]}"; do
      ./build/main -p 2 -trait 3 -log 0 -i 11 -d $dim -delta $delta -n $n -fake
    done
    echo
  done
done