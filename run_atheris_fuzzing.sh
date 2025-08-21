#!/bin/bash

# Local continuous fuzzing with Atheris
# This script runs Atheris-based fuzzers indefinitely
# NOTE: Atheris requires libFuzzer, which is only available on Linux

set -e

# Check if running on Linux
if [[ "$OSTYPE" != "linux-gnu"* ]]; then
    echo "Error: Atheris fuzzing is only supported on Linux."
    echo "On macOS, use the Hypothesis-based fuzzing instead:"
    echo "  ./run_fuzzing_continuous.sh"
    echo "  ./run_fuzzing_infinite.sh"
    exit 1
fi

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Configuration
FUZZER=${1:-"all"}  # Which fuzzer to run (tokenizer, parser, hypothesis, all)
MAX_RUNS=${MAX_RUNS:-"-1"}  # -1 for infinite, or specify number
MAX_LEN=${MAX_LEN:-"4096"}  # Maximum input length
SEED=${SEED:-"-1"}  # -1 for random seed
JOBS=${JOBS:-"4"}  # Number of parallel jobs
CORPUS_DIR=${CORPUS_DIR:-"corpus"}  # Directory for corpus

# Statistics
START_TIME=$(date +%s)
CURRENT_FUZZER=""

# Create corpus directory if it doesn't exist
mkdir -p "$CORPUS_DIR"

# Signal handler
cleanup() {
    echo -e "\n${YELLOW}Stopping Atheris fuzzing...${NC}"
    END_TIME=$(date +%s)
    RUNTIME=$((END_TIME - START_TIME))
    
    echo -e "\n${CYAN}╔════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║      ATHERIS FUZZING SUMMARY          ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════╝${NC}"
    echo -e "Runtime: ${GREEN}$((RUNTIME / 3600))h $((RUNTIME % 3600 / 60))m $((RUNTIME % 60))s${NC}"
    echo -e "Corpus directory: ${BLUE}${CORPUS_DIR}${NC}"
    
    # Check for crashes
    if [ -d "crash-*" ]; then
        echo -e "${RED}Crashes found! Check crash-* directories${NC}"
    fi
    
    exit 0
}

trap cleanup INT TERM

# Function to run a single fuzzer
run_fuzzer() {
    local fuzzer_name=$1
    local fuzzer_file="${fuzzer_name}_fuzzer.py"
    
    if [ ! -f "$fuzzer_file" ]; then
        echo -e "${RED}Fuzzer file $fuzzer_file not found${NC}"
        return 1
    fi
    
    echo -e "${BLUE}Starting $fuzzer_name fuzzer...${NC}"
    
    # Build Atheris arguments
    ATHERIS_ARGS=""
    
    # Add corpus directory
    ATHERIS_ARGS="$ATHERIS_ARGS ${CORPUS_DIR}/${fuzzer_name}"
    mkdir -p "${CORPUS_DIR}/${fuzzer_name}"
    
    # Add max runs if specified
    if [ "$MAX_RUNS" != "-1" ]; then
        ATHERIS_ARGS="$ATHERIS_ARGS -runs=$MAX_RUNS"
    fi
    
    # Add max length
    ATHERIS_ARGS="$ATHERIS_ARGS -max_len=$MAX_LEN"
    
    # Add seed if specified
    if [ "$SEED" != "-1" ]; then
        ATHERIS_ARGS="$ATHERIS_ARGS -seed=$SEED"
    fi
    
    # Add parallel jobs
    ATHERIS_ARGS="$ATHERIS_ARGS -jobs=$JOBS"
    
    # Run the fuzzer
    echo -e "${CYAN}Command: python3 $fuzzer_file $ATHERIS_ARGS${NC}"
    python3 "$fuzzer_file" $ATHERIS_ARGS
}

# Main execution
echo -e "${CYAN}╔════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║    ATHERIS CONTINUOUS FUZZING         ║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════╝${NC}"
echo -e "\nConfiguration:"
echo -e "  Fuzzer: ${GREEN}${FUZZER}${NC}"
echo -e "  Max runs: ${GREEN}${MAX_RUNS}${NC}"
echo -e "  Max length: ${GREEN}${MAX_LEN}${NC}"
echo -e "  Seed: ${GREEN}${SEED}${NC}"
echo -e "  Jobs: ${GREEN}${JOBS}${NC}"
echo -e "  Corpus: ${BLUE}${CORPUS_DIR}${NC}"
echo -e "\n${YELLOW}Press Ctrl+C to stop${NC}\n"

# Install atheris if not already installed
if ! python3 -c "import atheris" 2>/dev/null; then
    echo -e "${YELLOW}Installing atheris...${NC}"
    poetry add atheris --group dev
fi

# Run selected fuzzer(s)
case "$FUZZER" in
    tokenizer)
        run_fuzzer "tokenizer"
        ;;
    parser)
        run_fuzzer "parser"
        ;;
    hypothesis)
        run_fuzzer "hypothesis_structured"
        ;;
    all)
        # Run all fuzzers in sequence, each for a limited time
        while true; do
            echo -e "\n${MAGENTA}=== Fuzzing Round $(date '+%H:%M:%S') ===${NC}\n"
            
            # Run each fuzzer for 1000 runs
            MAX_RUNS=1000
            
            echo -e "${BLUE}[1/3] Tokenizer fuzzer${NC}"
            run_fuzzer "tokenizer" || true
            
            echo -e "\n${BLUE}[2/3] Parser fuzzer${NC}"
            run_fuzzer "parser" || true
            
            echo -e "\n${BLUE}[3/3] Hypothesis structured fuzzer${NC}"
            run_fuzzer "hypothesis_structured" || true
            
            echo -e "\n${GREEN}Round complete. Starting next round...${NC}"
            sleep 2
        done
        ;;
    *)
        echo -e "${RED}Unknown fuzzer: $FUZZER${NC}"
        echo "Available options: tokenizer, parser, hypothesis, all"
        exit 1
        ;;
esac