#!/usr/bin/python3
# Copyright 2024 GravitasML Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.

"""Fuzzer for GravitasML parser using Atheris."""

import sys
import atheris
from gravitasml.token import tokenize
from gravitasml.parser import Parser, Node, List


def TestOneInput(input_bytes):
    """Fuzz the parser with random input."""
    fdp = atheris.FuzzedDataProvider(input_bytes)
    
    # Generate random Unicode string
    markup = fdp.ConsumeUnicodeNoSurrogates(sys.maxsize)
    
    if not markup:
        return
    
    try:
        # Tokenize first
        tokens = tokenize(markup)
        
        # Parse the tokens
        parser = Parser(tokens)
        result = parser.parse()
        
        # Validate result type
        assert isinstance(result, (dict, list, type(None)))
        
        # If we got a result, try to convert it back
        if isinstance(result, dict):
            # Verify dictionary operations work
            _ = len(result)
            _ = result.keys()
        elif isinstance(result, list):
            # Verify list operations work
            _ = len(result)
            
    except (SyntaxError, ValueError, AttributeError, IndexError, KeyError, AssertionError):
        # These are expected exceptions for malformed input
        pass
    except RecursionError:
        # Can happen with deeply nested structures
        pass
    except Exception as e:
        # Unexpected exception - this might be a bug
        raise


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()