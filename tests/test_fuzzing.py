import pytest
from hypothesis import given, strategies as st, settings, assume
from hypothesis.strategies import text, composite
from gravitasml.token import tokenize, Token
from gravitasml.parser import Parser, Node, List
from pydantic import BaseModel
import re


class SampleModel(BaseModel):
    name: str = ""
    value: str = ""
    nested: dict = {}


@composite
def xml_like_markup(draw):
    """Generate XML-like markup for testing."""
    tag_name = draw(st.from_regex(r"[a-z][a-z0-9_]*", fullmatch=True))
    content = draw(st.text(min_size=0, max_size=100))

    choice = draw(st.integers(0, 4))

    if choice == 0:
        # Simple tag with content
        return f"<{tag_name}>{content}</{tag_name}>"
    elif choice == 1:
        # Nested tags
        inner = draw(xml_like_markup())
        return f"<{tag_name}>{inner}</{tag_name}>"
    elif choice == 2:
        # Multiple siblings
        inner1 = draw(xml_like_markup())
        inner2 = draw(xml_like_markup())
        return f"<{tag_name}>{inner1}{inner2}</{tag_name}>"
    elif choice == 3:
        # Text only
        return content
    else:
        # Empty tag
        return f"<{tag_name}></{tag_name}>"


@given(st.text())
@settings(max_examples=1000, deadline=None)
def test_tokenizer_with_random_input(markup):
    """Test tokenizer with completely random input."""
    try:
        tokens = tokenize(markup)

        # Verify token properties
        for token in tokens:
            assert isinstance(token, Token)
            assert token.type in ["TEXT", "TAG_OPEN", "TAG_CLOSE", "ESCAPE", "COMMENT"]
            assert isinstance(token.value, str)
            assert isinstance(token.line_num, int)
            assert isinstance(token.column, int)
            assert token.line_num >= 1
            assert token.column >= 0

            # Test token methods
            str(token)
            repr(token)
            assert token == token  # Test equality

    except (ValueError, AttributeError, IndexError, re.error):
        # Expected exceptions for malformed input
        pass


@given(xml_like_markup())
@settings(max_examples=500, deadline=None)
def test_parser_with_structured_markup(markup):
    """Test parser with structured XML-like markup."""
    try:
        tokens = tokenize(markup)
        parser = Parser(tokens)
        result = parser.parse()

        # Result should be either dict or list
        assert isinstance(result, (dict, list))

    except (SyntaxError, ValueError, AttributeError, IndexError, KeyError):
        # Expected exceptions for malformed input
        pass


@given(st.text(min_size=1, max_size=1000))
@settings(max_examples=500, deadline=None)
def test_parser_with_random_input(markup):
    """Test parser with completely random input."""
    try:
        tokens = tokenize(markup)
        parser = Parser(tokens)
        result = parser.parse()

        # Test pydantic parsing
        parser2 = Parser(tokens)
        parser2.parse_to_pydantic(SampleModel)

    except (SyntaxError, ValueError, AttributeError, IndexError, KeyError, Exception):
        # Expected exceptions for malformed input
        pass


@given(
    st.lists(st.tuples(st.sampled_from(["<", ">"]), st.text(min_size=0, max_size=20)))
)
@settings(max_examples=500, deadline=None)
def test_mismatched_tags(tag_pairs):
    """Test parser with potentially mismatched tags."""
    markup = ""
    for bracket, content in tag_pairs:
        markup += bracket + content

    try:
        tokens = tokenize(markup)
        parser = Parser(tokens)
        parser.parse()
    except (SyntaxError, ValueError, AttributeError, IndexError, KeyError):
        # Expected exceptions
        pass


@given(st.text(alphabet="<>\\/ \t\n", min_size=1, max_size=100))
@settings(max_examples=500, deadline=None)
def test_special_characters(markup):
    """Test with special characters that might break parsing."""
    try:
        tokens = tokenize(markup)
        parser = Parser(tokens)
        parser.parse()
    except (SyntaxError, ValueError, AttributeError, IndexError, KeyError):
        # Expected exceptions
        pass


@given(st.integers(1, 100))
@settings(max_examples=100, deadline=None)
def test_deeply_nested_tags(depth):
    """Test with deeply nested tag structures."""
    markup = ""
    tag_names = []

    # Create opening tags
    for i in range(depth):
        tag_name = f"tag{i}"
        tag_names.append(tag_name)
        markup += f"<{tag_name}>"

    markup += "content"

    # Create closing tags
    for tag_name in reversed(tag_names):
        markup += f"</{tag_name}>"

    try:
        tokens = tokenize(markup)
        parser = Parser(tokens)
        result = parser.parse()

        # Should successfully parse valid nested structure
        assert isinstance(result, dict)

    except RecursionError:
        # Might happen with very deep nesting
        assume(False)  # Skip this example


@given(st.text())
@settings(max_examples=500, deadline=None)
def test_node_operations(tag_name):
    """Test Node class operations with random input."""
    if not tag_name:
        tag_name = "default"

    try:
        node = Node(tag_name)
        child1 = Node("child1")
        child2 = Node("child2")

        node.add(child1)
        node.add(child2)

        # Test parent relationships
        assert child1.parent == node
        assert child2.parent == node

        # Test to_dict conversion
        result = node.to_dict()
        assert isinstance(result, dict)
        assert tag_name in result or "default" in result

    except (AttributeError, TypeError):
        # Might happen with certain tag names
        pass


@given(st.lists(st.text(min_size=1, max_size=20), min_size=0, max_size=10))
@settings(max_examples=500, deadline=None)
def test_list_operations(tag_names):
    """Test List class operations with random input."""
    lst = List()
    nodes = []

    for tag_name in tag_names:
        node = Node(tag_name)
        nodes.append(node)
        lst.add(node)

    # Test parent relationships
    for node in nodes:
        assert node.parent == lst

    # Test to_dict conversion
    result = lst.to_dict()
    assert isinstance(result, (dict, list))


@given(st.text(alphabet="<!---->", min_size=0, max_size=100))
@settings(max_examples=500, deadline=None)
def test_comment_handling(markup):
    """Test handling of HTML comments."""
    try:
        tokens = tokenize(markup)

        # Comments should be filtered out
        for token in tokens:
            assert token.type != "COMMENT"

    except (ValueError, re.error):
        # Expected for malformed comments
        pass


@given(st.text())
@settings(max_examples=500, deadline=None)
def test_escape_sequences(text):
    """Test handling of escape sequences."""
    # Add escape sequences
    markup = text.replace("<", "\\<").replace(">", "\\>")

    try:
        tokens = tokenize(markup)

        # The tokenizer may handle escapes differently
        # Just verify it doesn't crash and produces valid tokens
        for token in tokens:
            assert token.type in ["TEXT", "TAG_OPEN", "TAG_CLOSE", "ESCAPE", "COMMENT"]
            assert isinstance(token.value, str)

    except (ValueError, re.error):
        # Expected for certain inputs
        pass
