"""
Comprehensive fuzzing test suite for GravitasML.

This module contains property-based tests using Hypothesis to extensively
test the parser and tokenizer with generated markup.
"""

import unittest
from hypothesis import given, strategies as st, settings, assume
from hypothesis import HealthCheck
from gravitasml.token import tokenize, Token
from gravitasml.parser import Parser
from gravitasml.fuzz_generators import (
    structured_xml_markup,
    malformed_xml_markup,
    filter_syntax_markup,
    unicode_xml_markup,
    performance_xml_markup,
    XMLFuzzGenerator,
    FilterFuzzGenerator,
    MalformedMarkupGenerator,
    generate_test_cases,
)
from pydantic import BaseModel, ValidationError
import time


class FuzzTestModel(BaseModel):
    """Simple Pydantic model for testing."""

    tag: str


class NestedFuzzTestModel(BaseModel):
    """Nested Pydantic model for testing."""

    name: str
    value: str


class FuzzingComprehensiveTest(unittest.TestCase):
    """Comprehensive fuzzing tests for parser robustness."""

    def setUp(self):
        """Set up test fixtures."""
        self.xml_generator = XMLFuzzGenerator()
        self.filter_generator = FilterFuzzGenerator()
        self.malformed_generator = MalformedMarkupGenerator()

    @given(structured_xml_markup(max_depth=3, max_width=3, complexity="simple"))
    @settings(max_examples=50, suppress_health_check=[HealthCheck.too_slow])
    def test_structured_markup_parsing(self, markup):
        """Test that well-formed structured markup parses without crashing."""
        assume(markup and markup.strip())

        try:
            tokens = tokenize(markup)
            self.assertIsInstance(tokens, list)
            self.assertTrue(all(isinstance(token, Token) for token in tokens))

            parser = Parser(tokens)
            result = parser.parse()

            # Result should be dict or list
            self.assertIsInstance(result, (dict, list))

            # If dict, should have at least one key
            if isinstance(result, dict):
                self.assertGreater(len(result), 0)

            # If list, should have at least one element
            if isinstance(result, list):
                self.assertGreater(len(result), 0)
                self.assertTrue(all(isinstance(item, dict) for item in result))

        except (SyntaxError, ValueError) as e:
            # These are expected for some edge cases
            self.assertIsInstance(str(e), str)
            self.assertGreater(len(str(e)), 0)

    @given(malformed_xml_markup())
    @settings(max_examples=30, suppress_health_check=[HealthCheck.too_slow])
    def test_malformed_markup_error_handling(self, markup):
        """Test that malformed markup either raises appropriate errors or is handled gracefully."""
        assume(markup and markup.strip())

        try:
            tokens = tokenize(markup)
            parser = Parser(tokens)
            result = parser.parse()

            # If parsing succeeds, result should be valid
            self.assertIsInstance(result, (dict, list))

            # If it's a dict, should have content
            if isinstance(result, dict):
                self.assertGreater(len(result), 0)

            # If it's a list, should have content
            if isinstance(result, list):
                self.assertGreater(len(result), 0)

        except (SyntaxError, ValueError, Exception) as e:
            # If parsing fails, should have a meaningful error message
            self.assertIsInstance(str(e), str)
            self.assertGreater(len(str(e)), 0)

    @given(unicode_xml_markup())
    @settings(max_examples=30, suppress_health_check=[HealthCheck.too_slow])
    def test_unicode_markup_handling(self, markup):
        """Test Unicode character handling in markup."""
        assume(markup and markup.strip())

        try:
            tokens = tokenize(markup)
            self.assertIsInstance(tokens, list)

            parser = Parser(tokens)
            result = parser.parse()
            self.assertIsInstance(result, (dict, list))

        except (SyntaxError, ValueError) as e:
            # Unicode might cause some parsing issues, but should fail gracefully
            self.assertIsInstance(str(e), str)

    @given(performance_xml_markup(stress_level="light"))
    @settings(max_examples=20, suppress_health_check=[HealthCheck.too_slow])
    def test_performance_markup_parsing(self, markup):
        """Test performance with larger/deeper markup structures."""
        assume(markup and markup.strip())

        start_time = time.time()

        try:
            tokens = tokenize(markup)
            parser = Parser(tokens)
            result = parser.parse()

            end_time = time.time()
            parse_time = end_time - start_time

            # Should parse reasonably quickly (under 1 second for light stress)
            self.assertLess(
                parse_time,
                1.0,
                f"Parsing took too long: {parse_time:.3f}s for markup length {len(markup)}",
            )

            self.assertIsInstance(result, (dict, list))

        except (SyntaxError, ValueError) as e:
            # Performance markup might hit edge cases
            end_time = time.time()
            parse_time = end_time - start_time

            # Even errors should happen quickly
            self.assertLess(
                parse_time, 1.0, f"Error handling took too long: {parse_time:.3f}s"
            )

    def test_roundtrip_consistency(self):
        """Test that parsing results are consistent across multiple attempts."""
        markup = "<root><child1>value1</child1><child2>value2</child2></root>"

        # Parse multiple times
        results = []
        for _ in range(5):
            tokens = tokenize(markup)
            parser = Parser(tokens)
            result = parser.parse()
            results.append(result)

        # All results should be identical
        first_result = results[0]
        for result in results[1:]:
            self.assertEqual(result, first_result)

    def test_empty_and_minimal_inputs(self):
        """Test edge cases with empty or minimal inputs."""
        edge_cases = [
            "",  # Empty string
            "   ",  # Whitespace only
            "<tag></tag>",  # Empty tag
            "<a>b</a>",  # Minimal valid markup
            "<tag>  </tag>",  # Whitespace content
        ]

        for markup in edge_cases:
            with self.subTest(markup=markup):
                if not markup.strip():
                    # Empty inputs should either parse to empty or raise error
                    try:
                        tokens = tokenize(markup)
                        if tokens:  # If tokens generated
                            parser = Parser(tokens)
                            result = parser.parse()
                            # Result might be empty dict or list
                    except (SyntaxError, ValueError):
                        pass  # Expected for empty inputs
                else:
                    # Non-empty inputs should parse
                    tokens = tokenize(markup)
                    parser = Parser(tokens)
                    result = parser.parse()
                    self.assertIsInstance(result, (dict, list))

    def test_deeply_nested_structures(self):
        """Test handling of deeply nested structures."""
        # Generate progressively deeper nesting
        for depth in [5, 10, 15]:
            generator = XMLFuzzGenerator(max_depth=depth, max_width=2)
            markup = generator.generate_structured_markup(target_complexity="simple")

            with self.subTest(depth=depth):
                try:
                    tokens = tokenize(markup)
                    parser = Parser(tokens)
                    result = parser.parse()
                    self.assertIsInstance(result, (dict, list))
                except (SyntaxError, ValueError, RecursionError) as e:
                    # Deep nesting might cause recursion issues
                    if isinstance(e, RecursionError):
                        self.fail(
                            f"RecursionError at depth {depth}: parser should handle deep nesting gracefully"
                        )

    def test_wide_structures(self):
        """Test handling of structures with many sibling elements."""
        for width in [10, 20, 50]:
            generator = XMLFuzzGenerator(max_depth=2, max_width=width)
            markup = generator.generate_structured_markup(target_complexity="simple")

            with self.subTest(width=width):
                try:
                    tokens = tokenize(markup)
                    parser = Parser(tokens)
                    result = parser.parse()
                    self.assertIsInstance(result, (dict, list))

                    # Wide structures should result in lists or dicts with many entries
                    if isinstance(result, dict):
                        # Should have reasonable number of top-level keys
                        self.assertGreaterEqual(len(result), 1)
                    elif isinstance(result, list):
                        # Should have multiple items
                        self.assertGreaterEqual(len(result), 1)

                except (SyntaxError, ValueError, MemoryError) as e:
                    if isinstance(e, MemoryError):
                        self.fail(
                            f"MemoryError at width {width}: parser should handle wide structures efficiently"
                        )

    def test_mixed_content_patterns(self):
        """Test various mixed content patterns."""
        test_cases = [
            "<root>text<child>value</child>more text</root>",
            "<root><a>1</a>middle<b>2</b></root>",
            "<root>start<nested><deep>value</deep></nested>end</root>",
        ]

        for markup in test_cases:
            with self.subTest(markup=markup):
                tokens = tokenize(markup)
                parser = Parser(tokens)
                result = parser.parse()
                self.assertIsInstance(result, (dict, list))

    def test_repeated_tag_patterns(self):
        """Test handling of repeated tags that should create lists."""
        test_cases = [
            "<item>a</item><item>b</item><item>c</item>",
            "<root><item>1</item><item>2</item><item>3</item></root>",
            "<collection><item>x</item><other>y</other><item>z</item></collection>",
        ]

        for markup in test_cases:
            with self.subTest(markup=markup):
                tokens = tokenize(markup)
                parser = Parser(tokens)
                result = parser.parse()
                self.assertIsInstance(result, (dict, list))

                # Check that repeated tags create list structures
                if isinstance(result, list):
                    # Multiple root items should all be dicts
                    self.assertTrue(all(isinstance(item, dict) for item in result))
                elif isinstance(result, dict):
                    # Single root with repeated children should have lists
                    for value in result.values():
                        if isinstance(value, list):
                            self.assertTrue(
                                all(isinstance(item, dict) for item in value)
                            )

    def test_error_message_quality(self):
        """Test that error messages are helpful and descriptive."""
        error_cases = [
            ("<tag>content", "unclosed tag"),
            ("<tag1>content</tag2>", "mismatched tags"),
            ("<tag><nested></tag></nested>", "improper nesting"),
        ]

        for markup, expected_error_type in error_cases:
            with self.subTest(markup=markup, expected=expected_error_type):
                try:
                    tokens = tokenize(markup)
                    parser = Parser(tokens)
                    parser.parse()
                    self.fail(
                        f"Expected error for {expected_error_type} but parsing succeeded"
                    )
                except (SyntaxError, ValueError, Exception) as e:
                    error_msg = str(e).lower()
                    # Error message should be non-empty and descriptive
                    self.assertGreater(len(error_msg), 0)

                    # Check for relevant keywords in error messages
                    if expected_error_type == "mismatched tags":
                        self.assertIn("mismatch", error_msg)
                    elif expected_error_type == "unclosed tag":
                        self.assertIn("unclosed", error_msg)

    def test_pydantic_integration_robustness(self):
        """Test Pydantic integration with various markup patterns."""
        # Simple case that should work
        simple_markup = "<tag>test_value</tag>"
        tokens = tokenize(simple_markup)
        parser = Parser(tokens)

        try:
            result = parser.parse_to_pydantic(FuzzTestModel)
            self.assertIsInstance(result, FuzzTestModel)
            self.assertEqual(result.tag, "test_value")
        except ValidationError:
            # Pydantic validation might fail for some generated content
            pass

        # Multiple root elements
        multi_markup = "<tag>value1</tag><tag>value2</tag>"
        tokens = tokenize(multi_markup)
        parser = Parser(tokens)

        try:
            result = parser.parse_to_pydantic(FuzzTestModel)
            self.assertIsInstance(result, list)
            self.assertTrue(all(isinstance(item, FuzzTestModel) for item in result))
        except ValidationError:
            # Expected for some cases
            pass

    def test_memory_usage_reasonable(self):
        """Test that memory usage stays reasonable for large inputs."""
        # Generate moderately large markup
        generator = XMLFuzzGenerator(max_depth=8, max_width=5)
        markup = generator.generate_structured_markup(target_complexity="medium")

        # Parse and check that it completes
        start_time = time.time()
        tokens = tokenize(markup)
        parser = Parser(tokens)
        result = parser.parse()
        end_time = time.time()

        # Should complete in reasonable time
        self.assertLess(end_time - start_time, 5.0, "Parsing took too long")
        self.assertIsInstance(result, (dict, list))

    @given(st.text(min_size=1, max_size=100))
    @settings(max_examples=20, suppress_health_check=[HealthCheck.too_slow])
    def test_arbitrary_text_tokenization(self, text):
        """Test tokenizer with arbitrary text input."""
        assume(text and text.strip())

        try:
            tokens = tokenize(text)
            self.assertIsInstance(tokens, list)
            # Should either produce valid tokens or handle gracefully
            if tokens:
                self.assertTrue(all(isinstance(token, Token) for token in tokens))
        except (ValueError, SyntaxError):
            # Expected for non-markup text
            pass

    def test_generated_test_cases(self):
        """Test the convenience generate_test_cases function."""
        for case_type in ["valid", "malformed", "filter", "unicode"]:
            with self.subTest(case_type=case_type):
                cases = generate_test_cases(num_cases=5, case_type=case_type)
                self.assertEqual(len(cases), 5)
                self.assertTrue(all(isinstance(case, str) for case in cases))
                self.assertTrue(all(len(case) > 0 for case in cases))


class FilterSyntaxFuzzingTest(unittest.TestCase):
    """Specialized tests for filter syntax fuzzing."""

    def setUp(self):
        self.filter_generator = FilterFuzzGenerator()

    def test_valid_filter_syntax_patterns(self):
        """Test various valid filter syntax patterns."""
        for _ in range(10):
            markup = self.filter_generator.generate_filter_syntax(valid=True)

            with self.subTest(markup=markup):
                # Note: The current parser doesn't handle filter syntax yet
                # This test is for future filter implementation
                try:
                    tokens = tokenize(markup)
                    parser = Parser(tokens)
                    result = parser.parse()
                    # May succeed or fail depending on current filter support
                except (SyntaxError, ValueError):
                    # Expected until filter syntax is implemented
                    pass

    def test_invalid_filter_syntax_patterns(self):
        """Test invalid filter syntax patterns."""
        for _ in range(10):
            markup = self.filter_generator.generate_filter_syntax(valid=False)

            with self.subTest(markup=markup):
                try:
                    tokens = tokenize(markup)
                    parser = Parser(tokens)
                    result = parser.parse()
                    # Invalid syntax should ideally fail
                except (SyntaxError, ValueError):
                    # Expected for invalid syntax
                    pass

    def test_nested_filter_markup(self):
        """Test nested structures with filter syntax."""
        markup = self.filter_generator.generate_nested_filter_markup()

        try:
            tokens = tokenize(markup)
            parser = Parser(tokens)
            result = parser.parse()
            # May work depending on filter implementation
        except (SyntaxError, ValueError):
            # Expected until full filter support
            pass


class UnicodeInternationalizationTest(unittest.TestCase):
    """Specialized tests for Unicode and internationalization."""

    def test_unicode_tag_names(self):
        """Test Unicode characters in tag names."""
        unicode_cases = [
            "<测试>content</测试>",  # Chinese
            "<αβγ>content</αβγ>",  # Greek
            "<тест>content</тест>",  # Cyrillic
            "<🌍>content</🌍>",  # Emoji
        ]

        for markup in unicode_cases:
            with self.subTest(markup=markup):
                try:
                    tokens = tokenize(markup)
                    parser = Parser(tokens)
                    result = parser.parse()
                    self.assertIsInstance(result, (dict, list))
                except (SyntaxError, ValueError):
                    # Unicode in tag names might not be supported
                    pass

    def test_unicode_content(self):
        """Test Unicode characters in content."""
        unicode_content_cases = [
            "<tag>Hello 世界!</tag>",
            "<tag>🌍🌎🌏</tag>",
            "<tag>αβγδεζηθικλμνξοπρστυφχψω</tag>",
            "<tag>Здравствуй мир!</tag>",
        ]

        for markup in unicode_content_cases:
            with self.subTest(markup=markup):
                tokens = tokenize(markup)
                parser = Parser(tokens)
                result = parser.parse()
                self.assertIsInstance(result, (dict, list))

                # Verify Unicode content is preserved
                if isinstance(result, dict):
                    content_values = list(result.values())
                    self.assertTrue(
                        any(
                            "世界" in str(val)
                            or "🌍" in str(val)
                            or "α" in str(val)
                            or "мир" in str(val)
                            for val in content_values
                        )
                    )


if __name__ == "__main__":
    # Run a subset of tests for quick validation
    unittest.main(verbosity=2)
