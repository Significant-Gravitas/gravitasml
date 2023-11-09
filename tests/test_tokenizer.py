import unittest
from gravitasml.token import Token
from gravitasml.token import tokenize


class TestTokenizer(unittest.TestCase):
    def setUp(self):
        pass

    def test_single_tag(self):
        markup = "<tag>content</tag>"
        expected_output = [
            Token("TAG_OPEN", "tag", 1, 0),
            Token("TEXT", "content", 1, 5),
            Token("TAG_CLOSE", "tag", 1, 12),
        ]
        tokenized_output = tokenize(markup)
        self.assertEqual(tokenized_output, expected_output)

    def test_nested_tags(self):
        markup = "<tag1><tag2>content</tag2></tag1>"
        expected_output = [
            Token("TAG_OPEN", "tag1", 1, 0),
            Token("TAG_OPEN", "tag2", 1, 6),
            Token("TEXT", "content", 1, 12),
            Token("TAG_CLOSE", "tag2", 1, 19),
            Token("TAG_CLOSE", "tag1", 1, 26),
        ]
        tokenized_output = tokenize(markup)
        self.assertEqual(tokenized_output, expected_output)

    def test_tags_with_whitespace(self):
        markup = "<tag>   content with whitespace   </tag>"
        expected_output = [
            Token("TAG_OPEN", "tag", 1, 0),
            Token("TEXT", "content with whitespace", 1, 5),
            Token("TAG_CLOSE", "tag", 1, 34),
        ]
        tokenized_output = tokenize(markup)
        self.assertEqual(tokenized_output, expected_output)

    def test_multiple_root_tags(self):
        markup = "<tag1>content1</tag1><tag2>content2</tag2>"
        expected_output = [
            Token("TAG_OPEN", "tag1", 1, 0),
            Token("TEXT", "content1", 1, 6),
            Token("TAG_CLOSE", "tag1", 1, 14),
            Token("TAG_OPEN", "tag2", 1, 21),
            Token("TEXT", "content2", 1, 27),
            Token("TAG_CLOSE", "tag2", 1, 35),
        ]
        tokenized_output = tokenize(markup)
        self.assertEqual(tokenized_output, expected_output)

    def test_comment_ignored(self):
        markup = "<tag1>content <!-- a comment --> more content</tag1>"
        expected_output = [
            Token("TAG_OPEN", "tag1", 1, 0),
            Token("TEXT", "content", 1, 6),
            Token("TEXT", "more content", 1, 32),
            Token("TAG_CLOSE", "tag1", 1, 45),
        ]
        tokenized_output = tokenize(markup)
        self.assertEqual(tokenized_output, expected_output)

    # def test_self_closing_tags(self):
    #     markup = "<selfclosing />"
    #     with self.assertRaises(SyntaxError):
    #         tokens = tokenize(markup)
    #         print(tokens)

    def test_tags_with_underscores(self):
        markup = "<tag_name>content</tag_name>"
        expected_output = [
            Token("TAG_OPEN", "tag_name", 1, 0),
            Token("TEXT", "content", 1, 10),
            Token("TAG_CLOSE", "tag_name", 1, 17),
        ]
        tokenized_output = tokenize(markup)
        self.assertEqual(tokenized_output, expected_output)

    def test_tags_with_spaces(self):
        markup = "<tag name>content</tag name>"
        expected_output = [
            Token("TAG_OPEN", "tag_name", 1, 0),
            Token("TEXT", "content", 1, 10),
            Token("TAG_CLOSE", "tag_name", 1, 17),
        ]
        tokenized_output = tokenize(markup)
        self.assertEqual(tokenized_output, expected_output)

    def test_multiline_characters(self):
        markup = """
        <tag>
            <tag2>
                content
            </tag2>
        </tag>"""
        expected_output = [
            Token("TAG_OPEN", "tag", 1, 9),
            Token("TAG_OPEN", "tag2", 1, 27),
            Token("TEXT", "content", 1, 33),
            Token("TAG_CLOSE", "tag2", 1, 70),
            Token("TAG_CLOSE", "tag", 1, 86),
        ]
        tokenized_output = tokenize(markup)
        self.assertEqual(tokenized_output, expected_output)

    def test_multiline_characters_with_newline(self):
        markup = """
        <tag>
            <tag2>
                content\ntest
            </tag2>
        </tag>"""
        expected_output = [
            Token("TAG_OPEN", "tag", 1, 9),
            Token("TAG_OPEN", "tag2", 1, 27),
            Token("TEXT", "content\ntest", 1, 33),
            Token("TAG_CLOSE", "tag2", 1, 75),
            Token("TAG_CLOSE", "tag", 1, 91),
        ]
        tokenized_output = tokenize(markup)
        self.assertEqual(tokenized_output, expected_output)

    def test_empty_tag_content(self):
        markup = "<tag></tag>"
        expected_output = [
            Token("TAG_OPEN", "tag", 1, 0),
            Token("TAG_CLOSE", "tag", 1, 5),
        ]
        tokenized_output = tokenize(markup)
        self.assertEqual(tokenized_output, expected_output)

    def test_whitespace_around_tag_names(self):
        markup = "< tag >content</ tag >"
        expected_output = [
            Token("TAG_OPEN", "tag", 1, 0),
            Token("TEXT", "content", 1, 7),
            Token("TAG_CLOSE", "tag", 1, 14),
        ]
        tokenized_output = tokenize(markup)
        self.assertEqual(tokenized_output, expected_output)

    # def test_invalid_tag_syntax(self):
    #     markup = "<tag<content>>"
    #     with self.assertRaises(SyntaxError):
    #         tokens = tokenize(markup)
    #         print(tokens)

    def test_case_insensitivity(self):
        markup = "<TaG>cOnTeNt</TaG>"
        expected_output = [
            Token("TAG_OPEN", "tag", 1, 0),
            Token("TEXT", "cOnTeNt", 1, 5),
            Token("TAG_CLOSE", "tag", 1, 12),
        ]
        tokenized_output = tokenize(markup)
        self.assertEqual(tokenized_output, expected_output)

    def test_emoji_in_content(self):
        markup = "<tag>Content with emoji 😊</tag>"
        expected_output = [
            Token("TAG_OPEN", "tag", 1, 0),
            Token("TEXT", "Content with emoji 😊", 1, 5),
            Token("TAG_CLOSE", "tag", 1, 25),
        ]
        tokenized_output = tokenize(markup)
        self.assertEqual(tokenized_output, expected_output)

    def test_emoji_in_tag_name(self):
        markup = "<tag😊>Content in emoji tag</tag😊>"
        expected_output = [
            Token("TAG_OPEN", "tag😊", 1, 0),
            Token("TEXT", "Content in emoji tag", 1, 6),
            Token("TAG_CLOSE", "tag😊", 1, 26),  # type: ignore"
        ]

        tokenized_output = tokenize(markup)
        self.assertEqual(tokenized_output, expected_output)

    def test_mixed_content_with_tags_and_strings(self):
        markup = "<tag1>Here is some text <tag2>with a nested tag</tag2> and more text.</tag1>"
        expected_output = [
            Token("TAG_OPEN", "tag1", 1, 0),
            Token("TEXT", "Here is some text", 1, 6),
            Token("TAG_OPEN", "tag2", 1, 24),
            Token("TEXT", "with a nested tag", 1, 30),
            Token("TAG_CLOSE", "tag2", 1, 47),
            Token("TEXT", "and more text.", 1, 54),
            Token("TAG_CLOSE", "tag1", 1, 69),
        ]

        tokenized_output = tokenize(markup)
        self.assertEqual(tokenized_output, expected_output)

    def test_adjacent_tags_with_no_separation(self):
        markup = "<tag1>content1</tag1><tag2>content2</tag2>"
        expected_output = [
            Token("TAG_OPEN", "tag1", 1, 0),
            Token("TEXT", "content1", 1, 6),
            Token("TAG_CLOSE", "tag1", 1, 14),
            Token("TAG_OPEN", "tag2", 1, 21),
            Token("TEXT", "content2", 1, 27),
            Token("TAG_CLOSE", "tag2", 1, 35),
        ]
        tokenized_output = tokenize(markup)
        self.assertEqual(tokenized_output, expected_output)

    def test_tags_with_numerical_values(self):
        markup = "<tag123>content123</tag123>"
        expected_output = [
            Token("TAG_OPEN", "tag123", 1, 0),
            Token("TEXT", "content123", 1, 8),
            Token("TAG_CLOSE", "tag123", 1, 18),
        ]
        tokenized_output = tokenize(markup)
        self.assertEqual(tokenized_output, expected_output)

    def test_nested_tags_with_same_name(self):
        markup = "<tag><tag>Nested content</tag></tag>"
        expected_output = [
            Token("TAG_OPEN", "tag", 1, 0),
            Token("TAG_OPEN", "tag", 1, 5),
            Token("TEXT", "Nested content", 1, 10),
            Token("TAG_CLOSE", "tag", 1, 24),
            Token("TAG_CLOSE", "tag", 1, 30),
        ]
        tokenized_output = tokenize(markup)
        self.assertEqual(tokenized_output, expected_output)

    def test_large_input(self):
        markup = "<root>" + "<tag>content</tag>" * 20 + "</root>"
        expected_output = [
            Token("TAG_OPEN", "root", 1, 0),
            Token("TAG_OPEN", "tag", 1, 6),
            Token("TEXT", "content", 1, 11),
            Token("TAG_CLOSE", "tag", 1, 18),
            Token("TAG_OPEN", "tag", 1, 24),
            Token("TEXT", "content", 1, 29),
            Token("TAG_CLOSE", "tag", 1, 36),
            Token("TAG_OPEN", "tag", 1, 42),
            Token("TEXT", "content", 1, 47),
            Token("TAG_CLOSE", "tag", 1, 54),
            Token("TAG_OPEN", "tag", 1, 60),
            Token("TEXT", "content", 1, 65),
            Token("TAG_CLOSE", "tag", 1, 72),
            Token("TAG_OPEN", "tag", 1, 78),
            Token("TEXT", "content", 1, 83),
            Token("TAG_CLOSE", "tag", 1, 90),
            Token("TAG_OPEN", "tag", 1, 96),
            Token("TEXT", "content", 1, 101),
            Token("TAG_CLOSE", "tag", 1, 108),
            Token("TAG_OPEN", "tag", 1, 114),
            Token("TEXT", "content", 1, 119),
            Token("TAG_CLOSE", "tag", 1, 126),
            Token("TAG_OPEN", "tag", 1, 132),
            Token("TEXT", "content", 1, 137),
            Token("TAG_CLOSE", "tag", 1, 144),
            Token("TAG_OPEN", "tag", 1, 150),
            Token("TEXT", "content", 1, 155),
            Token("TAG_CLOSE", "tag", 1, 162),
            Token("TAG_OPEN", "tag", 1, 168),
            Token("TEXT", "content", 1, 173),
            Token("TAG_CLOSE", "tag", 1, 180),
            Token("TAG_OPEN", "tag", 1, 186),
            Token("TEXT", "content", 1, 191),
            Token("TAG_CLOSE", "tag", 1, 198),
            Token("TAG_OPEN", "tag", 1, 204),
            Token("TEXT", "content", 1, 209),
            Token("TAG_CLOSE", "tag", 1, 216),
            Token("TAG_OPEN", "tag", 1, 222),
            Token("TEXT", "content", 1, 227),
            Token("TAG_CLOSE", "tag", 1, 234),
            Token("TAG_OPEN", "tag", 1, 240),
            Token("TEXT", "content", 1, 245),
            Token("TAG_CLOSE", "tag", 1, 252),
            Token("TAG_OPEN", "tag", 1, 258),
            Token("TEXT", "content", 1, 263),
            Token("TAG_CLOSE", "tag", 1, 270),
            Token("TAG_OPEN", "tag", 1, 276),
            Token("TEXT", "content", 1, 281),
            Token("TAG_CLOSE", "tag", 1, 288),
            Token("TAG_OPEN", "tag", 1, 294),
            Token("TEXT", "content", 1, 299),
            Token("TAG_CLOSE", "tag", 1, 306),
            Token("TAG_OPEN", "tag", 1, 312),
            Token("TEXT", "content", 1, 317),
            Token("TAG_CLOSE", "tag", 1, 324),
            Token("TAG_OPEN", "tag", 1, 330),
            Token("TEXT", "content", 1, 335),
            Token("TAG_CLOSE", "tag", 1, 342),
            Token("TAG_OPEN", "tag", 1, 348),
            Token("TEXT", "content", 1, 353),
            Token("TAG_CLOSE", "tag", 1, 360),
            Token("TAG_CLOSE", "root", 1, 366),
        ]
        tokenized_output = tokenize(markup)
        self.assertEqual(tokenized_output, expected_output)

    @unittest.expectedFailure
    def test_escaped_characters(self):
        markup = r"<tag>Escaped \<tag> content</tag>"
        expected_output = [
            Token("TAG_OPEN", "tag", 1, 0),
            Token("TEXT", "Escaped <tag> content", 1, 5),
            Token("TAG_CLOSE", "tag", 1, 27),
        ]
        tokenized_output = tokenize(markup)
        self.assertEqual(tokenized_output, expected_output)

    @unittest.expectedFailure
    def test_consecutive_escaped_characters(self):
        markup = r"<tag>\\\\\<content\\</tag>"
        expected_output = [
            Token("TAG_OPEN", "tag", 1, 0),
            Token("TEXT", "\\", 1, 5),
            Token("TEXT", "\\", 1, 7),
            Token("TEXT", "<", 1, 9),
            Token("TEXT", "content", 1, 11),
            Token("TEXT", "\\", 1, 7),
            Token("TAG_CLOSE", "tag", 1, 17),
        ]
        tokenized_output = tokenize(markup)
        self.assertEqual(tokenized_output, expected_output)


if __name__ == "__main__":
    unittest.main()
