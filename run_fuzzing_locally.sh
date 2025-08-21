#!/bin/bash

echo "Running property-based fuzz tests with Hypothesis..."

# Run the fuzz tests with pytest
poetry run pytest tests/test_fuzzing.py -v --hypothesis-show-statistics

echo "Fuzzing complete."