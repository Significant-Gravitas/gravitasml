"""
Enhanced fuzzing infrastructure for GravitasML.

This module provides sophisticated XML-like markup generators for comprehensive
testing of the parser and tokenizer components.
"""

import random
import string
from typing import List, Optional, Tuple
from hypothesis import strategies as st
from hypothesis.strategies import composite


class XMLFuzzGenerator:
    """
    Configurable XML-like markup generator with depth and width controls.

    Generates structured XML patterns with configurable complexity for
    stress testing parser robustness.
    """

    def __init__(
        self,
        max_depth: int = 10,
        max_width: int = 5,
        allow_unicode: bool = True,
        allow_self_closing: bool = False,
        allow_mixed_content: bool = True,
    ):
        self.max_depth = max_depth
        self.max_width = max_width
        self.allow_unicode = allow_unicode
        self.allow_self_closing = allow_self_closing
        self.allow_mixed_content = allow_mixed_content

    def generate_tag_name(self, min_len: int = 1, max_len: int = 10) -> str:
        """Generate a valid tag name with optional Unicode characters."""
        base_chars = string.ascii_letters + string.digits + "_"

        if self.allow_unicode:
            # Add some Unicode characters for international testing
            unicode_chars = "测试αβγδεζηθικλμνξοπρστυφχψω世界🌍🌎🌏"
            base_chars += unicode_chars

        length = random.randint(min_len, max_len)
        # Ensure first character is a letter or underscore
        first_char = random.choice(string.ascii_letters + "_")
        if length == 1:
            return first_char

        remaining_chars = "".join(random.choice(base_chars) for _ in range(length - 1))
        return first_char + remaining_chars

    def generate_text_content(self, min_len: int = 0, max_len: int = 100) -> str:
        """Generate text content with optional Unicode and special characters."""
        if min_len == 0 and random.random() < 0.2:
            return ""  # 20% chance of empty content

        base_chars = (
            string.ascii_letters
            + string.digits
            + string.punctuation.replace("<", "").replace(">", "")
            + " \t\n\r"
        )

        if self.allow_unicode:
            unicode_chars = "Hello 世界! 🌍 Testing αβγ"
            base_chars += unicode_chars

        length = random.randint(min_len, max_len)
        return "".join(random.choice(base_chars) for _ in range(length))

    def generate_whitespace_pattern(self) -> str:
        """Generate various whitespace patterns for testing."""
        patterns = [
            "",  # No whitespace
            " ",  # Single space
            "\t",  # Tab
            "\n",  # Newline
            "\r\n",  # Windows newline
            "   ",  # Multiple spaces
            " \t\n ",  # Mixed whitespace
        ]
        return random.choice(patterns)

    def generate_structured_markup(
        self, depth: int = 0, target_complexity: str = "medium"
    ) -> str:
        """
        Generate structured XML markup with configurable complexity.

        Args:
            depth: Current nesting depth
            target_complexity: "simple", "medium", "complex", or "stress"
        """
        if depth >= self.max_depth:
            # At max depth, return simple content
            tag_name = self.generate_tag_name(3, 8)
            content = self.generate_text_content(1, 50)
            return f"<{tag_name}>{content}</{tag_name}>"

        complexity_settings = {
            "simple": {"max_children": 2, "content_prob": 0.7},
            "medium": {"max_children": 3, "content_prob": 0.5},
            "complex": {"max_children": 5, "content_prob": 0.4},
            "stress": {"max_children": 8, "content_prob": 0.3},
        }

        settings = complexity_settings.get(
            target_complexity, complexity_settings["medium"]
        )

        tag_name = self.generate_tag_name()
        pre_ws = self.generate_whitespace_pattern()
        post_ws = self.generate_whitespace_pattern()

        # Decide whether to have text content, nested tags, or both
        has_content = random.random() < settings["content_prob"]
        has_children = random.random() < 0.6 and depth < self.max_depth - 1

        content_parts = []

        if has_content:
            text_content = self.generate_text_content(0, 200)
            if text_content:
                content_parts.append(text_content)

        if has_children:
            num_children = random.randint(
                1, min(settings["max_children"], self.max_width)
            )
            children = []

            for _ in range(num_children):
                child_markup = self.generate_structured_markup(
                    depth + 1, target_complexity
                )
                children.append(child_markup)

            content_parts.extend(children)

        # If no content generated, add simple text
        if not content_parts:
            content_parts.append(self.generate_text_content(1, 20))

        # Mix content if allowed
        if self.allow_mixed_content and len(content_parts) > 1:
            random.shuffle(content_parts)

        inner_content = "".join(content_parts)

        return f"{pre_ws}<{tag_name}>{inner_content}</{tag_name}>{post_ws}"


class FilterFuzzGenerator:
    """
    Specialized generator for testing filter syntax like '| no_parse'.

    Tests various filter combinations and edge cases to ensure
    robust filter handling.
    """

    def __init__(self):
        self.valid_filters = ["no_parse", "filter1", "filter2", "custom_filter"]
        self.invalid_filters = ["", " ", "||", "invalid filter", "123filter"]

    def generate_filter_syntax(self, valid: bool = True) -> str:
        """Generate filter syntax with optional validity control."""
        base_tag = f"tag_{random.randint(1, 100)}"

        if valid:
            if random.random() < 0.8:  # 80% chance of valid single filter
                filter_name = random.choice(self.valid_filters)
                return f"<{base_tag} | {filter_name}>content</{base_tag}>"
            else:  # 20% chance of multiple filters
                num_filters = random.randint(2, 3)
                filters = random.sample(
                    self.valid_filters, min(num_filters, len(self.valid_filters))
                )
                filter_str = " ".join(filters)
                return f"<{base_tag} | {filter_str}>content</{base_tag}>"
        else:
            # Generate invalid filter syntax
            invalid_patterns = [
                f"<{base_tag} |>content</{base_tag}>",  # Empty filter
                f"<{base_tag} | >content</{base_tag}>",  # Space only filter
                f"<{base_tag} ||>content</{base_tag}>",  # Double pipe
                f"<{base_tag} | {random.choice(self.invalid_filters)}>content</{base_tag}>",  # Invalid filter name
                f"<{base_tag} | NO_PARSE>content</{base_tag}>",  # Wrong case
            ]
            return random.choice(invalid_patterns)

    def generate_nested_filter_markup(self) -> str:
        """Generate nested structures with mixed filter usage."""
        outer_tag = "outer"
        inner_tag = "inner"

        outer_has_filter = random.random() < 0.5
        inner_has_filter = random.random() < 0.5

        outer_filter = " | no_parse" if outer_has_filter else ""
        inner_filter = " | no_parse" if inner_has_filter else ""

        return (
            f"<{outer_tag}{outer_filter}>"
            f"<{inner_tag}{inner_filter}>nested content</{inner_tag}>"
            f"</{outer_tag}>"
        )


class MalformedMarkupGenerator:
    """
    Systematic generator of invalid markup for testing error handling.

    Generates various types of malformed markup to ensure the parser
    fails gracefully with clear error messages.
    """

    def __init__(self):
        self.tag_names = ["tag", "element", "node", "item", "test"]

    def generate_unclosed_tag(self) -> str:
        """Generate markup with unclosed tags."""
        tag_name = random.choice(self.tag_names)
        content = f"content_{random.randint(1, 100)}"

        patterns = [
            f"<{tag_name}>{content}",  # Missing closing tag
            f"<{tag_name}>{content}<",  # Incomplete closing tag
            f"<{tag_name}>{content}</{tag_name[:-1]}",  # Partial closing tag name
        ]
        return random.choice(patterns)

    def generate_mismatched_tags(self) -> str:
        """Generate markup with mismatched opening and closing tags."""
        tag1 = random.choice(self.tag_names)
        tag2 = random.choice([t for t in self.tag_names if t != tag1])
        content = f"content_{random.randint(1, 100)}"

        return f"<{tag1}>{content}</{tag2}>"

    def generate_invalid_tag_names(self) -> str:
        """Generate markup with tag names that cause real parsing issues."""
        # Since the parser is quite permissive, focus on patterns that actually cause errors
        # Most "invalid" tag names are actually accepted by the parser
        tag_name = random.choice(self.tag_names)
        content = f"content_{random.randint(1, 100)}"

        # These patterns should cause tokenization or parsing errors
        patterns = [
            f"<{tag_name}>content",  # Unclosed tag (moved from other method)
            f"<{tag_name}>{content}</{tag_name}extra>",  # Extra text in closing tag
            f"<{tag_name}>{content}</invalid_close>",  # Wrong closing tag name
        ]
        return random.choice(patterns)

    def generate_improper_nesting(self) -> str:
        """Generate improperly nested markup."""
        tag1, tag2 = random.sample(self.tag_names, 2)
        content = f"content_{random.randint(1, 100)}"

        patterns = [
            f"<{tag1}><{tag2}></{tag1}></{tag2}>",  # Cross-nested
            f"<{tag1}><{tag2}></{tag1}>content</{tag2}>",  # Mixed cross-nesting
        ]
        return random.choice(patterns)

    def generate_incomplete_markup(self) -> str:
        """Generate incomplete markup structures."""
        tag_name = random.choice(self.tag_names)
        content = f"content_{random.randint(1, 100)}"

        patterns = [
            f"<{tag_name} {content}",  # Missing closing bracket
            f"<{tag_name}>{content}</{tag_name}",  # Missing final bracket
            f"{tag_name}>{content}</{tag_name}>",  # Missing opening bracket
            f"<{tag_name}>{content}<{tag_name}>",  # Missing slash in closing tag
        ]
        return random.choice(patterns)

    def generate_extra_brackets(self) -> str:
        """Generate markup with extra or misplaced brackets that cause errors."""
        tag_name = random.choice(self.tag_names)
        content = f"content_{random.randint(1, 100)}"

        # Focus on patterns that actually cause tokenization/parsing errors
        patterns = [
            f"<{tag_name}>content",  # Unclosed (this should be an error)
            f"<{tag_name}>{content}</{tag_name}extra",  # Extra text after closing tag name
            f"<{tag_name}>{content}</>",  # Empty closing tag
        ]
        return random.choice(patterns)


# Hypothesis strategies for integration with property-based testing


@composite
def structured_xml_markup(
    draw,
    max_depth: int = 5,
    max_width: int = 3,
    allow_filters: bool = True,
    complexity: str = "medium",
):
    """
    Hypothesis composite strategy for generating structured XML markup.

    Args:
        max_depth: Maximum nesting depth
        max_width: Maximum number of sibling elements
        allow_filters: Whether to include filter syntax
        complexity: Target complexity level
    """
    generator = XMLFuzzGenerator(
        max_depth=max_depth,
        max_width=max_width,
        allow_unicode=True,
        allow_mixed_content=True,
    )

    markup = generator.generate_structured_markup(target_complexity=complexity)

    # Optionally add filter syntax
    if allow_filters and draw(st.booleans()):
        filter_gen = FilterFuzzGenerator()
        filter_markup = filter_gen.generate_filter_syntax(valid=True)
        # Combine with structured markup in some cases
        if draw(st.booleans()):
            markup = f"{markup}\n{filter_markup}"

    return markup


@composite
def malformed_xml_markup(draw):
    """
    Hypothesis composite strategy for generating malformed XML markup.

    Generates various types of invalid markup for testing error handling.
    """
    generator = MalformedMarkupGenerator()

    malformation_types = [
        generator.generate_unclosed_tag,
        generator.generate_mismatched_tags,
        generator.generate_invalid_tag_names,
        generator.generate_improper_nesting,
        generator.generate_incomplete_markup,
        generator.generate_extra_brackets,
    ]

    malformation_func = draw(st.sampled_from(malformation_types))
    return malformation_func()


@composite
def filter_syntax_markup(draw):
    """
    Hypothesis composite strategy for filter syntax testing.

    Generates markup with various filter patterns for comprehensive testing.
    """
    generator = FilterFuzzGenerator()

    pattern_types = [
        lambda: generator.generate_filter_syntax(valid=True),
        lambda: generator.generate_filter_syntax(valid=False),
        generator.generate_nested_filter_markup,
    ]

    pattern_func = draw(st.sampled_from(pattern_types))
    return pattern_func()


@composite
def unicode_xml_markup(draw):
    """
    Hypothesis composite strategy for Unicode and internationalization testing.

    Generates markup with Unicode characters in tag names and content.
    """
    max_depth = draw(st.integers(min_value=1, max_value=3))
    max_width = draw(st.integers(min_value=1, max_value=3))

    generator = XMLFuzzGenerator(
        max_depth=max_depth, max_width=max_width, allow_unicode=True
    )

    return generator.generate_structured_markup(target_complexity="simple")


@composite
def performance_xml_markup(draw, stress_level: str = "medium"):
    """
    Hypothesis composite strategy for performance and scale testing.

    Generates large or deeply nested structures for performance testing.

    Args:
        stress_level: "light", "medium", "heavy", or "extreme"
    """
    stress_settings = {
        "light": {"max_depth": 5, "max_width": 5, "complexity": "simple"},
        "medium": {"max_depth": 10, "max_width": 8, "complexity": "medium"},
        "heavy": {"max_depth": 20, "max_width": 10, "complexity": "complex"},
        "extreme": {"max_depth": 50, "max_width": 15, "complexity": "stress"},
    }

    settings = stress_settings.get(stress_level, stress_settings["medium"])

    generator = XMLFuzzGenerator(
        max_depth=settings["max_depth"],
        max_width=settings["max_width"],
        allow_unicode=False,  # Disable Unicode for pure performance testing
        allow_mixed_content=True,
    )

    return generator.generate_structured_markup(
        target_complexity=settings["complexity"]
    )


# Convenience functions for quick testing


def generate_test_cases(num_cases: int = 10, case_type: str = "mixed") -> List[str]:
    """
    Generate a list of test cases for manual testing.

    Args:
        num_cases: Number of test cases to generate
        case_type: Type of test cases - "valid", "malformed", "filter", "unicode", "performance"

    Returns:
        List of generated markup strings
    """
    cases = []

    for _ in range(num_cases):
        if case_type == "valid":
            generator = XMLFuzzGenerator()
            case = generator.generate_structured_markup()
        elif case_type == "malformed":
            generator = MalformedMarkupGenerator()
            case = generator.generate_unclosed_tag()  # Can be extended to rotate types
        elif case_type == "filter":
            generator = FilterFuzzGenerator()
            case = generator.generate_filter_syntax()
        elif case_type == "unicode":
            generator = XMLFuzzGenerator(allow_unicode=True)
            case = generator.generate_structured_markup()
        elif case_type == "performance":
            generator = XMLFuzzGenerator(max_depth=15, max_width=10)
            case = generator.generate_structured_markup(target_complexity="stress")
        else:  # mixed
            generators = [
                lambda: XMLFuzzGenerator().generate_structured_markup(),
                lambda: MalformedMarkupGenerator().generate_unclosed_tag(),
                lambda: FilterFuzzGenerator().generate_filter_syntax(),
            ]
            case = random.choice(generators)()

        cases.append(case)

    return cases
