#!/bin/bash
set -e

EXAMPLES_DIR="examples"
RUN_DURATION=5
TIMEOUT_CMD="timeout"

# Find all fuzzer projects in the examples directory.
for fuzzer_path in "$EXAMPLES_DIR"/*; do
    if [ -d "$fuzzer_path" ]; then
        fuzzer_name=$(basename "$fuzzer_path")
        echo "Building fuzzer: $fuzzer_name"
        CANISTER_FORCE_BUILD=1 cargo build --release -p "$fuzzer_name"
        echo "Running fuzzer: $fuzzer_name"
        CANISTER_FORCE_BUILD=1 $TIMEOUT_CMD "${RUN_DURATION}s" cargo run --release -p "$fuzzer_name" || [ $? -eq 124 ]
    fi
done

echo "All fuzzers have been run."