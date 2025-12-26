# Fuzzing GravitasML

This document describes the fuzzing infrastructure for GravitasML, which uses both Atheris (Google's Python fuzzing engine) and Hypothesis for comprehensive fuzz testing.

## Overview

GravitasML employs two complementary fuzzing approaches:

1. **[Atheris](https://github.com/google/atheris)** - Coverage-guided fuzzing engine for Python, compatible with OSS-Fuzz
2. **[Hypothesis](https://hypothesis.readthedocs.io/)** - Property-based testing for structured input generation

This dual approach enables both unstructured fuzzing (finding crashes and edge cases) and structured fuzzing (testing with valid XML-like markup).

## Quick Start

### Hypothesis-based Fuzzing (Property Testing)

```bash
# Install dependencies
poetry install

# Run hypothesis tests
./run_fuzzing_locally.sh

# Run continuous hypothesis fuzzing (runs forever)
./run_fuzzing_continuous.sh

# Run infinite fuzzing with adaptive strategies
./run_fuzzing_infinite.sh

# Run specific test with more examples
poetry run pytest tests/test_fuzzing.py::test_parser_with_random_input --hypothesis-max-examples=10000
```

### Atheris-based Fuzzing (OSS-Fuzz Compatible)

**Note:** Atheris requires libFuzzer which is only available on Linux. On macOS, use the Hypothesis-based fuzzing instead.

```bash
# On Linux only - Install atheris
poetry install --with fuzzing

# Run all Atheris fuzzers continuously (Linux only)
./run_atheris_fuzzing.sh all

# Run specific fuzzer
./run_atheris_fuzzing.sh tokenizer  # or parser, hypothesis

# Run with custom settings
MAX_RUNS=10000 JOBS=8 ./run_atheris_fuzzing.sh all
```

## Test Coverage

The fuzzing tests cover:

1. **Tokenizer robustness** - Random input strings to test tokenization
2. **Parser correctness** - Structured and random XML-like markup
3. **Edge cases** - Deeply nested tags, mismatched tags, special characters
4. **Error handling** - Malformed input, syntax errors
5. **Memory safety** - No crashes or undefined behavior
6. **Data structure operations** - Node and List class methods

## Fuzzing Components

### Hypothesis Tests (tests/test_fuzzing.py)

- `test_tokenizer_with_random_input` - Tests tokenizer with completely random strings
- `test_parser_with_structured_markup` - Tests parser with generated XML-like structures
- `test_parser_with_random_input` - Tests full parsing pipeline with random input
- `test_mismatched_tags` - Tests parser with potentially mismatched opening/closing tags
- `test_special_characters` - Tests handling of special characters (<, >, /, etc.)
- `test_deeply_nested_tags` - Tests parser with deeply nested tag structures
- `test_node_operations` - Tests Node class methods with random input
- `test_list_operations` - Tests List class methods with random input
- `test_comment_handling` - Tests HTML comment parsing
- `test_escape_sequences` - Tests escape sequence handling

### Atheris Fuzzers (OSS-Fuzz Compatible)

- `tokenizer_fuzzer.py` - Coverage-guided fuzzing of the tokenizer
- `parser_fuzzer.py` - Coverage-guided fuzzing of the parser
- `hypothesis_structured_fuzzer.py` - Combines Atheris with Hypothesis for structured fuzzing

## OSS-Fuzz Integration

The project is configured for [OSS-Fuzz](https://github.com/google/oss-fuzz) integration:

```
ossfuzz/
├── Dockerfile       # Build environment with Atheris
├── build.sh        # Builds fuzzers using compile_python_fuzzer
└── project.yaml    # Project configuration

# Atheris fuzzers (OSS-Fuzz compatible)
tokenizer_fuzzer.py
parser_fuzzer.py
hypothesis_structured_fuzzer.py
```

### Testing OSS-Fuzz Locally

```bash
# Clone OSS-Fuzz
git clone https://github.com/google/oss-fuzz.git
cd oss-fuzz

# Copy our config
cp -r /path/to/gravitasml/ossfuzz projects/gravitasml
cp /path/to/gravitasml/*_fuzzer.py projects/gravitasml/

# Build fuzzers
python infra/helper.py build_fuzzers gravitasml

# Run a specific fuzzer
python infra/helper.py run_fuzzer gravitasml tokenizer_fuzzer

# Check coverage
python infra/helper.py coverage gravitasml
```

## Writing New Fuzz Tests

### Hypothesis Test (Property-based)

Add to `tests/test_fuzzing.py`:

```python
from hypothesis import given, strategies as st, settings

@given(st.text())  # Generate random text input
@settings(max_examples=1000, deadline=None)
def test_my_new_fuzzer(input_data):
    # Your test logic here
    try:
        result = your_function(input_data)
        # Add assertions about expected behavior
        assert some_property(result)
    except ExpectedException:
        # Handle expected exceptions
        pass
```

### Atheris Fuzzer (OSS-Fuzz Compatible)

Create a new file `my_fuzzer.py`:

```python
#!/usr/bin/python3
import sys
import atheris
from gravitasml import your_module

def TestOneInput(input_bytes):
    """Fuzz target function."""
    fdp = atheris.FuzzedDataProvider(input_bytes)
    
    # Generate fuzzed input
    data = fdp.ConsumeUnicodeNoSurrogates(sys.maxsize)
    
    try:
        # Test your code
        result = your_module.process(data)
        # Add assertions
        assert validate(result)
    except ExpectedException:
        # Expected exceptions are OK
        pass

def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
```

## Hypothesis Strategies

We use custom Hypothesis strategies for generating test data:

- `xml_like_markup()` - Generates valid XML-like markup structures
- `st.text()` - Random Unicode strings
- `st.lists()` - Lists of values
- `st.integers()` - Random integers in ranges

## Security Considerations

The fuzzing tests help identify:

- **Input validation issues** - Malformed input handling
- **ReDoS vulnerabilities** - Regular expression denial of service
- **Memory issues** - Buffer overflows, excessive memory usage
- **Logic errors** - Incorrect parsing, data corruption
- **Error disclosure** - Information leakage in error messages

## Continuous Fuzzing

Once integrated with OSS-Fuzz, the project will be continuously fuzzed with:

- Daily fuzzing runs
- Automatic bug reporting
- Regression testing
- Coverage tracking

## Running with Different Seeds

Hypothesis tests are deterministic by default. To test with different seeds:

```bash
# Random seed each run
poetry run pytest tests/test_fuzzing.py --hypothesis-seed=random

# Specific seed for reproduction
poetry run pytest tests/test_fuzzing.py --hypothesis-seed=12345
```

## Performance Tuning

Adjust fuzzing intensity:

```bash
# Quick smoke test (100 examples each)
poetry run pytest tests/test_fuzzing.py --hypothesis-max-examples=100

# Thorough testing (10000 examples each)
poetry run pytest tests/test_fuzzing.py --hypothesis-max-examples=10000

# Profile slow tests
poetry run pytest tests/test_fuzzing.py --hypothesis-profile=dev
```

## Known Limitations

- Some deeply nested structures may cause RecursionError (handled gracefully)
- Regex patterns in tokenizer have theoretical ReDoS potential (mitigated by input size limits)
- Unicode edge cases may behave differently across platforms

## Contributing

When adding new parsing features:

1. Add corresponding fuzz tests
2. Run fuzzing locally before committing
3. Ensure all tests pass with at least 1000 examples
4. Document any new expected exceptions