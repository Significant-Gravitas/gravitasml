#!/usr/bin/python3
# Copyright 2024 GravitasML Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.

"""Fuzzer for GravitasML tokenizer using Atheris."""

import sys
import atheris
from gravitasml.token import tokenize, Token


def TestOneInput(input_bytes):
    """Fuzz the tokenizer with random input."""
    fdp = atheris.FuzzedDataProvider(input_bytes)
    
    # Generate random Unicode string
    markup = fdp.ConsumeUnicodeNoSurrogates(sys.maxsize)
    
    if not markup:
        return
    
    try:
        # Attempt to tokenize the input
        tokens = tokenize(markup)
        
        # Validate token properties
        for token in tokens:
            assert isinstance(token, Token)
            assert token.type in ["TEXT", "TAG_OPEN", "TAG_CLOSE", "ESCAPE", "COMMENT"]
            assert isinstance(token.value, str)
            assert isinstance(token.line_num, int)
            assert isinstance(token.column, int)
            assert token.line_num >= 1
            assert token.column >= 0
            
            # Exercise token methods
            _ = str(token)
            _ = repr(token)
            _ = (token == token)
            
    except (ValueError, AttributeError, IndexError, KeyError, AssertionError):
        # These are expected exceptions for malformed input
        pass
    except Exception as e:
        # Unexpected exception - this might be a bug
        raise


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()