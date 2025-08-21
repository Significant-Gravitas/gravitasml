#!/bin/bash

# Infinite fuzzing script with adaptive strategies
# This script runs forever, increasing test complexity over time

set -e

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Configuration
BASE_EXAMPLES=${BASE_EXAMPLES:-1000}
GROWTH_FACTOR=${GROWTH_FACTOR:-1.1}  # Increase examples by 10% each cycle
MAX_EXAMPLES_LIMIT=${MAX_EXAMPLES_LIMIT:-100000}  # Maximum examples per test
PARALLEL_JOBS=${PARALLEL_JOBS:-4}  # Number of parallel test processes
LOG_FILE=${LOG_FILE:-"fuzzing_$(date +%Y%m%d_%H%M%S).log"}

# Statistics
TOTAL_ITERATIONS=0
TOTAL_EXAMPLES=0
BUGS_FOUND=0
CURRENT_EXAMPLES=$BASE_EXAMPLES
START_TIME=$(date +%s)

# Create log file
echo "Continuous Fuzzing Log - Started $(date)" > "$LOG_FILE"

# Signal handler
cleanup() {
    echo -e "\n${YELLOW}Shutting down infinite fuzzing...${NC}"
    END_TIME=$(date +%s)
    RUNTIME=$((END_TIME - START_TIME))
    
    echo -e "\n${CYAN}╔════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║         FUZZING SESSION SUMMARY        ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════╝${NC}"
    echo -e "Total iterations: ${GREEN}${TOTAL_ITERATIONS}${NC}"
    echo -e "Total examples tested: ${GREEN}${TOTAL_EXAMPLES}${NC}"
    echo -e "Bugs found: ${RED}${BUGS_FOUND}${NC}"
    echo -e "Runtime: ${GREEN}$((RUNTIME / 3600))h $((RUNTIME % 3600 / 60))m $((RUNTIME % 60))s${NC}"
    echo -e "Log file: ${BLUE}${LOG_FILE}${NC}"
    
    # Log summary
    {
        echo "=== Session Summary ==="
        echo "End time: $(date)"
        echo "Total iterations: ${TOTAL_ITERATIONS}"
        echo "Total examples: ${TOTAL_EXAMPLES}"
        echo "Bugs found: ${BUGS_FOUND}"
        echo "Runtime: $((RUNTIME / 3600))h $((RUNTIME % 3600 / 60))m $((RUNTIME % 60))s"
    } >> "$LOG_FILE"
    
    exit 0
}

trap cleanup INT TERM

# Function to run a test suite
run_test_suite() {
    local test_name=$1
    local examples=$2
    local seed=$3
    local iteration=$4
    
    echo -e "${MAGENTA}[Test: ${test_name}]${NC} Examples: ${examples}, Seed: ${seed}"
    
    # Set Hypothesis environment variables
    export HYPOTHESIS_PROFILE="fuzzing"
    export HYPOTHESIS_MAX_EXAMPLES="${examples}"
    
    # Run the specific test
    if poetry run pytest "tests/test_fuzzing.py::${test_name}" \
        --hypothesis-profile=fuzzing \
        --hypothesis-seed="${seed}" \
        -q 2>&1 | tee -a "$LOG_FILE" | grep -E "(FAILED|ERROR|passed)" ; then
        return 0
    else
        return 1
    fi
}

# Main header
echo -e "${CYAN}╔════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║    INFINITE FUZZING MODE ACTIVATED    ║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════╝${NC}"
echo -e "\nConfiguration:"
echo -e "  Base examples: ${GREEN}${BASE_EXAMPLES}${NC}"
echo -e "  Growth factor: ${GREEN}${GROWTH_FACTOR}${NC}"
echo -e "  Max examples: ${GREEN}${MAX_EXAMPLES_LIMIT}${NC}"
echo -e "  Parallel jobs: ${GREEN}${PARALLEL_JOBS}${NC}"
echo -e "  Log file: ${BLUE}${LOG_FILE}${NC}"
echo -e "\n${YELLOW}Press Ctrl+C to stop (will show summary)${NC}\n"

# Test list
TESTS=(
    "test_tokenizer_with_random_input"
    "test_parser_with_structured_markup"
    "test_parser_with_random_input"
    "test_mismatched_tags"
    "test_special_characters"
    "test_deeply_nested_tags"
    "test_node_operations"
    "test_list_operations"
    "test_comment_handling"
    "test_escape_sequences"
)

# Infinite loop
while true; do
    TOTAL_ITERATIONS=$((TOTAL_ITERATIONS + 1))
    
    # Calculate current examples (grows over time)
    CURRENT_EXAMPLES=$(echo "$CURRENT_EXAMPLES * $GROWTH_FACTOR" | bc | cut -d. -f1)
    if [ "$CURRENT_EXAMPLES" -gt "$MAX_EXAMPLES_LIMIT" ]; then
        CURRENT_EXAMPLES=$BASE_EXAMPLES  # Reset when hitting limit
        echo -e "${YELLOW}Reset examples to base value${NC}"
    fi
    
    echo -e "\n${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}Iteration ${TOTAL_ITERATIONS} | Examples: ${CURRENT_EXAMPLES}${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    # Log iteration
    {
        echo "=== Iteration ${TOTAL_ITERATIONS} ==="
        echo "Time: $(date)"
        echo "Examples per test: ${CURRENT_EXAMPLES}"
    } >> "$LOG_FILE"
    
    # Different strategies for different iterations
    STRATEGY=$((TOTAL_ITERATIONS % 3))
    
    case $STRATEGY in
        0)
            echo -e "${CYAN}Strategy: Random seeds${NC}"
            for test in "${TESTS[@]}"; do
                SEED=$RANDOM
                if ! run_test_suite "$test" "$CURRENT_EXAMPLES" "$SEED" "$TOTAL_ITERATIONS"; then
                    BUGS_FOUND=$((BUGS_FOUND + 1))
                    echo -e "${RED}Bug found in ${test}! (Seed: ${SEED})${NC}" | tee -a "$LOG_FILE"
                fi
                TOTAL_EXAMPLES=$((TOTAL_EXAMPLES + CURRENT_EXAMPLES))
            done
            ;;
        1)
            echo -e "${CYAN}Strategy: Fixed seed, increasing complexity${NC}"
            SEED=42
            for test in "${TESTS[@]}"; do
                if ! run_test_suite "$test" "$CURRENT_EXAMPLES" "$SEED" "$TOTAL_ITERATIONS"; then
                    BUGS_FOUND=$((BUGS_FOUND + 1))
                    echo -e "${RED}Bug found in ${test}!${NC}" | tee -a "$LOG_FILE"
                fi
                TOTAL_EXAMPLES=$((TOTAL_EXAMPLES + CURRENT_EXAMPLES))
            done
            ;;
        2)
            echo -e "${CYAN}Strategy: Parallel execution${NC}"
            # Run tests in parallel using xargs
            export HYPOTHESIS_PROFILE="fuzzing"
            export HYPOTHESIS_MAX_EXAMPLES="${CURRENT_EXAMPLES}"
            printf "%s\n" "${TESTS[@]}" | xargs -P "$PARALLEL_JOBS" -I {} bash -c "
                HYPOTHESIS_PROFILE=fuzzing HYPOTHESIS_MAX_EXAMPLES=${CURRENT_EXAMPLES} poetry run pytest 'tests/test_fuzzing.py::{}' \
                    --hypothesis-profile=fuzzing \
                    --hypothesis-seed=\$RANDOM \
                    -q 2>&1 | grep -E '(FAILED|ERROR|passed|PASSED)' || true
            "
            TOTAL_EXAMPLES=$((TOTAL_EXAMPLES + CURRENT_EXAMPLES * ${#TESTS[@]}))
            ;;
    esac
    
    # Memory usage check
    if command -v free &> /dev/null; then
        MEM_USAGE=$(free -m | awk 'NR==2{printf "%.1f%%", $3*100/$2}')
        echo -e "Memory usage: ${YELLOW}${MEM_USAGE}${NC}"
    fi
    
    # Progress report
    CURRENT_TIME=$(date +%s)
    RUNTIME=$((CURRENT_TIME - START_TIME))
    RATE=$((TOTAL_EXAMPLES / (RUNTIME + 1)))  # Examples per second
    
    echo -e "\n${GREEN}Progress Report:${NC}"
    echo -e "  Runtime: $((RUNTIME / 3600))h $((RUNTIME % 3600 / 60))m"
    echo -e "  Total examples: ${TOTAL_EXAMPLES}"
    echo -e "  Rate: ~${RATE} examples/sec"
    echo -e "  Bugs found: ${RED}${BUGS_FOUND}${NC}"
    
    # No delay - run continuously
    echo -e "${BLUE}Continuing to next iteration...${NC}"
done