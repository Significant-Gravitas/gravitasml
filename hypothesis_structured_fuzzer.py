#!/usr/bin/python3
# Copyright 2024 GravitasML Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.

"""Structured fuzzer for GravitasML using Hypothesis with Atheris."""

import sys
import atheris
from hypothesis import given, strategies as st, settings
from gravitasml.token import tokenize
from gravitasml.parser import Parser
from pydantic import BaseModel


class TestModel(BaseModel):
    """Test model for Pydantic parsing."""
    name: str = ""
    value: str = ""
    nested: dict = {}
    items: list = []


# Define strategies for generating XML-like markup
TAG_NAME = st.from_regex(r"[a-zA-Z][a-zA-Z0-9_]*", fullmatch=True)
TEXT_CONTENT = st.text(min_size=0, max_size=100)

def xml_markup(max_depth=5):
    """Strategy for generating XML-like markup."""
    if max_depth <= 0:
        return TEXT_CONTENT
    
    return st.one_of(
        # Text only
        TEXT_CONTENT,
        # Self-closing tag
        st.builds(lambda name: f"<{name}/>", TAG_NAME),
        # Tag with text content
        st.builds(
            lambda name, content: f"<{name}>{content}</{name}>",
            TAG_NAME,
            TEXT_CONTENT
        ),
        # Tag with nested content
        st.builds(
            lambda name, inner: f"<{name}>{inner}</{name}>",
            TAG_NAME,
            st.deferred(lambda: xml_markup(max_depth - 1))
        ),
        # Multiple siblings
        st.builds(
            lambda name, inner1, inner2: f"<{name}>{inner1}{inner2}</{name}>",
            TAG_NAME,
            st.deferred(lambda: xml_markup(max_depth - 1)),
            st.deferred(lambda: xml_markup(max_depth - 1))
        )
    )


@given(markup=xml_markup())
@settings(max_examples=1, deadline=None)
@atheris.instrument_func
def test_parser_roundtrip(markup):
    """Test that valid XML-like markup can be parsed."""
    try:
        # Tokenize
        tokens = tokenize(markup)
        
        # Parse to dict/list
        parser = Parser(tokens)
        result = parser.parse()
        
        # Validate result
        assert isinstance(result, (dict, list, type(None)))
        
        # Try Pydantic parsing
        parser2 = Parser(tokens)
        model = parser2.parse_to_pydantic(TestModel)
        assert isinstance(model, TestModel)
        
    except (SyntaxError, ValueError, AttributeError, IndexError, KeyError):
        # Expected exceptions for certain inputs
        pass
    except RecursionError:
        # Can happen with deeply nested structures
        pass


@given(
    tag_names=st.lists(TAG_NAME, min_size=1, max_size=10),
    contents=st.lists(TEXT_CONTENT, min_size=1, max_size=10)
)
@settings(max_examples=1, deadline=None)
@atheris.instrument_func
def test_nested_tags(tag_names, contents):
    """Test parsing of nested tag structures."""
    # Build nested structure
    markup = ""
    for tag in tag_names:
        markup += f"<{tag}>"
    
    # Add content in the middle
    markup += contents[0] if contents else "content"
    
    # Close tags in reverse order
    for tag in reversed(tag_names):
        markup += f"</{tag}>"
    
    try:
        tokens = tokenize(markup)
        parser = Parser(tokens)
        result = parser.parse()
        
        # Should successfully parse valid nested structure
        assert isinstance(result, (dict, list))
        
    except (SyntaxError, ValueError, RecursionError):
        # May fail with very deep nesting or other issues
        pass


def main():
    # For OSS-Fuzz, we need to use the Hypothesis fuzzer interface
    if len(sys.argv) > 1 and sys.argv[1] == "--hypothesis":
        # Run with Hypothesis directly
        test_parser_roundtrip()
        test_nested_tags()
    else:
        # Run with Atheris
        atheris.Setup(
            sys.argv, 
            atheris.instrument_func(
                test_parser_roundtrip.hypothesis.fuzz_one_input
            )
        )
        atheris.Fuzz()


if __name__ == "__main__":
    main()