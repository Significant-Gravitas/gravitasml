#!/bin/bash

# Continuous fuzzing script for GravitasML
# This script runs fuzzing tests indefinitely until interrupted

set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
MAX_EXAMPLES=${MAX_EXAMPLES:-10000}  # Number of examples per test per iteration
SEED_MODE=${SEED_MODE:-"random"}     # Use "random" for different seeds each iteration
ITERATION_DELAY=${ITERATION_DELAY:-5} # Seconds between iterations
VERBOSE=${VERBOSE:-false}            # Set to true for verbose output

# Statistics
TOTAL_ITERATIONS=0
TOTAL_EXAMPLES=0
START_TIME=$(date +%s)

# Signal handler for graceful shutdown
cleanup() {
    echo -e "\n${YELLOW}Stopping continuous fuzzing...${NC}"
    END_TIME=$(date +%s)
    RUNTIME=$((END_TIME - START_TIME))
    
    echo -e "\n${BLUE}=== Fuzzing Statistics ===${NC}"
    echo -e "Total iterations: ${GREEN}${TOTAL_ITERATIONS}${NC}"
    echo -e "Total examples tested: ${GREEN}${TOTAL_EXAMPLES}${NC}"
    echo -e "Runtime: ${GREEN}$((RUNTIME / 3600))h $((RUNTIME % 3600 / 60))m $((RUNTIME % 60))s${NC}"
    
    if [ $TOTAL_ITERATIONS -gt 0 ]; then
        AVG_EXAMPLES=$((TOTAL_EXAMPLES / TOTAL_ITERATIONS))
        echo -e "Average examples per iteration: ${GREEN}${AVG_EXAMPLES}${NC}"
    fi
    
    exit 0
}

trap cleanup INT TERM

echo -e "${BLUE}=== Starting Continuous Fuzzing for GravitasML ===${NC}"
echo -e "Configuration:"
echo -e "  Max examples per test: ${GREEN}${MAX_EXAMPLES}${NC}"
echo -e "  Seed mode: ${GREEN}${SEED_MODE}${NC}"
echo -e "  Iteration delay: ${GREEN}${ITERATION_DELAY}s${NC}"
echo -e "  Verbose: ${GREEN}${VERBOSE}${NC}"
echo -e "\nPress ${YELLOW}Ctrl+C${NC} to stop fuzzing\n"

# Main fuzzing loop
while true; do
    TOTAL_ITERATIONS=$((TOTAL_ITERATIONS + 1))
    
    echo -e "${BLUE}=== Iteration ${TOTAL_ITERATIONS} ===${NC}"
    echo -e "Starting at: $(date '+%Y-%m-%d %H:%M:%S')"
    
    # Generate random seed if in random mode
    if [ "$SEED_MODE" = "random" ]; then
        SEED=$RANDOM
        echo -e "Using seed: ${YELLOW}${SEED}${NC}"
        SEED_ARG="--hypothesis-seed=${SEED}"
    else
        SEED_ARG=""
    fi
    
    # Build pytest command
    PYTEST_CMD="poetry run pytest tests/test_fuzzing.py"
    
    # Set Hypothesis environment variables
    export HYPOTHESIS_PROFILE="fuzzing"
    export HYPOTHESIS_MAX_EXAMPLES="${MAX_EXAMPLES}"
    
    PYTEST_ARGS="--hypothesis-profile=fuzzing ${SEED_ARG}"
    
    if [ "$VERBOSE" = "true" ]; then
        PYTEST_ARGS="${PYTEST_ARGS} -v --hypothesis-show-statistics"
    else
        PYTEST_ARGS="${PYTEST_ARGS} -q"
    fi
    
    # Run fuzzing tests
    if $PYTEST_CMD $PYTEST_ARGS; then
        echo -e "${GREEN}✓ Iteration ${TOTAL_ITERATIONS} completed successfully${NC}"
        
        # Estimate number of examples tested (10 tests * MAX_EXAMPLES)
        ITERATION_EXAMPLES=$((10 * MAX_EXAMPLES))
        TOTAL_EXAMPLES=$((TOTAL_EXAMPLES + ITERATION_EXAMPLES))
        
    else
        EXIT_CODE=$?
        echo -e "${RED}✗ Fuzzing found an issue in iteration ${TOTAL_ITERATIONS}!${NC}"
        echo -e "${YELLOW}Exit code: ${EXIT_CODE}${NC}"
        
        if [ "$SEED_MODE" = "random" ]; then
            echo -e "${YELLOW}To reproduce, run:${NC}"
            echo -e "${BLUE}HYPOTHESIS_MAX_EXAMPLES=${MAX_EXAMPLES} poetry run pytest tests/test_fuzzing.py --hypothesis-profile=fuzzing --hypothesis-seed=${SEED} -v${NC}"
        fi
        
        # Ask user whether to continue
        echo -e "\n${YELLOW}Continue fuzzing? (y/n/r for reproduce):${NC}"
        read -r response
        
        case $response in
            [yY])
                echo -e "${GREEN}Continuing...${NC}"
                ;;
            [rR])
                echo -e "${BLUE}Running reproduction with verbose output...${NC}"
                HYPOTHESIS_MAX_EXAMPLES=${MAX_EXAMPLES} poetry run pytest tests/test_fuzzing.py --hypothesis-profile=fuzzing --hypothesis-seed=${SEED} -vv
                echo -e "\n${YELLOW}Continue fuzzing? (y/n):${NC}"
                read -r cont_response
                if [[ ! $cont_response =~ ^[yY]$ ]]; then
                    cleanup
                fi
                ;;
            *)
                cleanup
                ;;
        esac
    fi
    
    # Show progress
    CURRENT_TIME=$(date +%s)
    RUNTIME=$((CURRENT_TIME - START_TIME))
    echo -e "Runtime: $((RUNTIME / 3600))h $((RUNTIME % 3600 / 60))m $((RUNTIME % 60))s | Examples tested: ~${TOTAL_EXAMPLES}"
    
    # Delay between iterations (unless it's the first iteration)
    if [ $ITERATION_DELAY -gt 0 ]; then
        echo -e "${BLUE}Waiting ${ITERATION_DELAY} seconds before next iteration...${NC}\n"
        sleep $ITERATION_DELAY
    fi
done