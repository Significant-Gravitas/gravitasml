import unittest

from pydantic import BaseModel
from gravitasml.token import tokenize
from gravitasml.parser import Parser


class TestParser(unittest.TestCase):
    def test_single_tag(self):
        markup = "<tag>content</tag>"
        tokens = tokenize(markup)
        parser = Parser(tokens)
        object = parser.parse()
        correct = {"tag": "content"}
        self.assertEqual(correct, object)

    def test_convert_to_pydantic_model_single(self):
        class MyModel(BaseModel):
            tag: str

        markup = "<tag>content</tag>"
        tokens = tokenize(markup)
        parser = Parser(tokens)
        object = parser.parse_to_pydantic(MyModel)
        self.assertEqual(object, MyModel(tag="content"))

    def test_double_duplicate_tag(self):
        markup = "<tag>content</tag><tag>content</tag>"
        tokens = tokenize(markup)
        parser = Parser(tokens)
        object = parser.parse()
        correct = [{"tag": "content"}, {"tag": "content"}]
        self.assertEqual(correct, object)

    def test_convert_to_pydantic_model_list(self):
        class MyModel(BaseModel):
            tag: str

        markup = "<tag>content</tag><tag>content</tag>"
        tokens = tokenize(markup)
        parser = Parser(tokens)
        object = parser.parse_to_pydantic(MyModel)
        self.assertEqual(object, [MyModel(tag="content"), MyModel(tag="content")])

    def test_nested_tags(self):
        markup = "<tag1><tag2>content</tag2></tag1>"
        tokens = tokenize(markup)
        parser = Parser(tokens)
        object = parser.parse()
        correct = {"tag1": {"tag2": "content"}}
        self.assertEqual(correct, object)

    def test_nested_tags_pydantic(self):
        class Tag2(BaseModel):
            tag2: str

        class Tag1(BaseModel):
            tag1: Tag2

        markup = "<tag1><tag2>content</tag2></tag1>"
        tokens = tokenize(markup)
        parser = Parser(tokens)
        object = parser.parse_to_pydantic(Tag1)
        self.assertEqual(object, Tag1(tag1=Tag2(tag2="content")))

    def test_double_duplicate_tag_nested_duplicate(self):
        markup = "<tag><1>a</1><1>a</1></tag><tag><1>a</1><1>a</1></tag>"
        tokens = tokenize(markup)
        parser = Parser(tokens)
        object = parser.parse()
        correct = [{"tag": [{"1": "a"}, {"1": "a"}]}, {"tag": [{"1": "a"}, {"1": "a"}]}]
        self.assertEqual(correct, object)

    def test_tags_with_whitespace(self):
        markup = "<tag>   content with whitespace   </tag>"
        tokens = tokenize(markup)
        parser = Parser(tokens)
        object = parser.parse()
        correct = {"tag": "content with whitespace"}
        self.assertEqual(correct, object)

    def test_multiple_root_tags(self):
        markup = "<tag1>content1</tag1><tag2>content2</tag2>"
        tokens = tokenize(markup)
        parser = Parser(tokens)
        object = parser.parse()
        correct = {"tag1": "content1", "tag2": "content2"}
        self.assertEqual(correct, object)

    def test_repeated_tags_to_list(self):
        markup = "<tag><a>value</a><a>value</a></tag>"
        tokens = tokenize(markup)
        parser = Parser(tokens)
        object = parser.parse()
        correct = {
            "tag": [
                {"a": "value"},
                {"a": "value"},
            ]
        }

        self.assertEqual(correct, object)

    def test_non_repeated_tags(self):
        markup = "<tag><a>value</a><b>value</b></tag>"
        tokens = tokenize(markup)
        parser = Parser(tokens)
        object = parser.parse()
        correct = {"tag": {"a": "value", "b": "value"}}
        self.assertEqual(correct, object)

    def test_non_repeated_tags_multiline(self):
        markup = """
        <tag>
            <a>
                value
            </a>
            <b>
                value
            </b>
        </tag>
        """
        tokens = tokenize(markup)
        parser = Parser(tokens)
        object = parser.parse()
        correct = {"tag": {"a": "value", "b": "value"}}
        self.assertEqual(correct, object)

    def test_non_repeated_tags_multiline_divergent_children(self):
        markup = """
        <tag>
            <a>
                <test>
                    pass
                </test>
                <test>
                    fail
                </test>
            </a>
            <b>
                value
            </b>
            <c>
                <test>
                    <name>
                        Test 1
                    </name>
                    <result>
                        pass
                    </result>
                </test>
                <test>
                    <name>
                        Test 2
                    </name>
                    <result>
                        fail
                    </result>
                    <feeling>
                        rough crowd
                    </feeling>
                </test>
            </c>
        </tag>
        """
        tokens = tokenize(markup)
        parser = Parser(tokens)
        object = parser.parse()
        correct = {
            "tag": {
                "a": [{"test": "pass"}, {"test": "fail"}],
                "b": "value",
                "c": [
                    {"test": {"name": "Test 1", "result": "pass"}},
                    {
                        "test": {
                            "name": "Test 2",
                            "result": "fail",
                            "feeling": "rough crowd",
                        }
                    },
                ],
            }
        }

        self.assertEqual(correct, object)

    def test_non_repeated_tags_multiline_divergent_children_duplicate_root(self):
        markup = """
        <tag>
            <a>
                <test>
                    pass
                </test>
                <test>
                    fail
                </test>
            </a>
            <b>
                value
            </b>
            <c>
                <test>
                    <name>
                        Test 1
                    </name>
                    <result>
                        pass
                    </result>
                </test>
                <test>
                    <name>
                        Test 2
                    </name>
                    <result>
                        fail
                    </result>
                    <feeling>
                        rough crowd
                    </feeling>
                </test>
            </c>
        </tag>
        <tag>
        heyo
        </tag>
        """
        tokens = tokenize(markup)
        parser = Parser(tokens)
        object = parser.parse()
        correct = [
            {
                "tag": {
                    "a": [{"test": "pass"}, {"test": "fail"}],
                    "b": "value",
                    "c": [
                        {"test": {"name": "Test 1", "result": "pass"}},
                        {
                            "test": {
                                "name": "Test 2",
                                "result": "fail",
                                "feeling": "rough crowd",
                            }
                        },
                    ],
                }
            },
            {"tag": "heyo"},
        ]
        self.assertEqual(correct, object)

    @unittest.expectedFailure
    def test_escaped_characters(self):
        markup = r"<tag>Escaped \<tag> content</tag>"
        tokens = tokenize(markup)
        parser = Parser(tokens)
        object = parser.parse()
        correct = [{"tag": "Escaped <tag> content"}]
        self.assertEqual(correct, object)

    @unittest.expectedFailure
    def test_escaped_characters_new_line(self):
        markup = "<tag>Escaped \<tag> content\n</tag>"
        tokens = tokenize(markup)
        parser = Parser(tokens)
        object = parser.parse()
        correct = [{"tag": "Escaped <tag> content"}]
        self.assertEqual(correct, object)

    def test_escaped_characters_carrage_return(self):
        markup = "<tag>Escaped \r content\n</tag>"
        tokens = tokenize(markup)
        parser = Parser(tokens)
        object = parser.parse()
        correct = {"tag": "Escaped \r content"}
        self.assertEqual(correct, object)

    def test_escaped_characters_carrage_return_mulitple_root_tags(self):
        markup = "<tag>Escaped \r content\n</tag><tag>Escaped \r content\n</tag>"
        tokens = tokenize(markup)
        parser = Parser(tokens)
        object = parser.parse()
        correct = [{"tag": "Escaped \r content"}, {"tag": "Escaped \r content"}]
        self.assertEqual(correct, object)

    @unittest.expectedFailure
    def test_consecutive_escaped_characters(self):
        markup = r"<tag>\\\\\<content\\</tag>"
        tokens = tokenize(markup)
        parser = Parser(tokens)
        object = parser.parse()
        correct = [{"tag": r"\\\\<content\\"}]
        self.assertEqual(correct, object)

    def test_incomplete_tag(self):
        markup = "<tag>Content with an <incomplete"
        with self.assertRaises(SyntaxError):
            tokens = tokenize(markup)
            parser = Parser(tokens)
            object = parser.parse()

    def test_unmatched_tag(self):
        markup = "<tag1>content</tag2>"
        with self.assertRaises(SyntaxError):  # or whatever error your parser raises
            tokens = tokenize(markup)
            parser = Parser(tokens)
            object = parser.parse()

    def test_improperly_nested_tags(self):
        markup = "<tag1><tag2></tag1></tag2>"
        with self.assertRaises(
            SyntaxError
        ) as context:  # assuming improper nesting raises a SyntaxError
            tokens = tokenize(markup)
            parser = Parser(tokens)
            object = parser.parse()
        print(str(context.exception))

        self.assertTrue("Mismatched tags: tag2 and tag1" in str(context.exception))

    def test_no_parse_filter_basic(self):
        markup = "<tag | no_parse><inner>content</inner></tag>"
        tokens = tokenize(markup)
        parser = Parser(tokens)
        object = parser.parse()
        correct = {"tag": "<inner>content</inner>"}
        self.assertEqual(correct, object)

    def test_no_parse_filter_mixed_parsing(self):
        markup = "<root><normal>parsed</normal><raw | no_parse><inner>not parsed</inner></raw></root>"
        tokens = tokenize(markup)
        parser = Parser(tokens)
        object = parser.parse()
        correct = {"root": {"normal": "parsed", "raw": "<inner>not parsed</inner>"}}
        self.assertEqual(correct, object)

    def test_no_parse_filter_nested_same_tag(self):
        markup = "<tag | no_parse><tag>nested</tag></tag>"
        tokens = tokenize(markup)
        parser = Parser(tokens)
        object = parser.parse()
        correct = {"tag": "<tag>nested</tag>"}
        self.assertEqual(correct, object)

    def test_no_parse_filter_complex_content(self):
        markup = '<html | no_parse><div class="test"><p>Hello <strong>world</strong></p></div></html>'
        tokens = tokenize(markup)
        parser = Parser(tokens)
        object = parser.parse()
        # Note: spaces between tags are stripped by tokenizer, but attributes are preserved
        correct = {"html": '<div class="test"><p>Hello<strong>world</strong></p></div>'}
        self.assertEqual(correct, object)

    def test_no_parse_filter_empty_content(self):
        markup = "<tag | no_parse></tag>"
        tokens = tokenize(markup)
        parser = Parser(tokens)
        object = parser.parse()
        correct = {"tag": ""}
        self.assertEqual(correct, object)

    def test_no_parse_filter_with_text_content(self):
        markup = "<tag | no_parse>Just plain text content</tag>"
        tokens = tokenize(markup)
        parser = Parser(tokens)
        object = parser.parse()
        correct = {"tag": "Just plain text content"}
        self.assertEqual(correct, object)

    def test_multiple_no_parse_filters(self):
        markup = "<root><first | no_parse><a>1</a></first><second | no_parse><b>2</b></second></root>"
        tokens = tokenize(markup)
        parser = Parser(tokens)
        object = parser.parse()
        correct = {"root": {"first": "<a>1</a>", "second": "<b>2</b>"}}
        self.assertEqual(correct, object)

    def test_no_parse_with_whitespace(self):
        markup = """<tag | no_parse>
        <inner>
            content with whitespace
        </inner>
        </tag>"""
        tokens = tokenize(markup)
        parser = Parser(tokens)
        object = parser.parse()
        # The tokenizer strips whitespace from text tokens, so whitespace between tags is removed
        expected_content = """<inner>content with whitespace</inner>"""
        correct = {"tag": expected_content}
        self.assertEqual(correct, object)

    # Additional positive test cases
    def test_no_parse_with_multiple_filters(self):
        markup = "<tag | no_parse other_filter><content>test</content></tag>"
        tokens = tokenize(markup)
        parser = Parser(tokens)
        object = parser.parse()
        correct = {"tag": "<content>test</content>"}
        self.assertEqual(correct, object)

    def test_no_parse_deeply_nested(self):
        markup = "<outer | no_parse><level1><level2><level3>deep content</level3></level2></level1></outer>"
        tokens = tokenize(markup)
        parser = Parser(tokens)
        object = parser.parse()
        correct = {"outer": "<level1><level2><level3>deep content</level3></level2></level1>"}
        self.assertEqual(correct, object)

    def test_no_parse_with_special_characters(self):
        markup = '<code | no_parse>function test() { return "hello & goodbye"; }</code>'
        tokens = tokenize(markup)
        parser = Parser(tokens)
        object = parser.parse()
        correct = {"code": 'function test() { return "hello & goodbye"; }'}
        self.assertEqual(correct, object)

    def test_no_parse_with_mixed_quotes(self):
        markup = """<script | no_parse>var x = 'single'; var y = "double";</script>"""
        tokens = tokenize(markup)
        parser = Parser(tokens)
        object = parser.parse()
        correct = {"script": """var x = 'single'; var y = "double";"""}
        self.assertEqual(correct, object)

    def test_no_parse_with_self_closing_like_syntax(self):
        markup = "<xml | no_parse><img src='test.jpg'/><br/></xml>"
        tokens = tokenize(markup)
        parser = Parser(tokens)
        object = parser.parse()
        # Self-closing syntax is not recognized as tags by the tokenizer, so they become text
        correct = {"xml": "img src='test.jpg'/>br/>"}
        self.assertEqual(correct, object)

    def test_no_parse_with_numbers_and_symbols(self):
        markup = "<data | no_parse>123 + 456 = 579 @#$%^&*()</data>"
        tokens = tokenize(markup)
        parser = Parser(tokens)
        object = parser.parse()
        correct = {"data": "123 + 456 = 579 @#$%^&*()"}
        self.assertEqual(correct, object)

    def test_no_parse_with_newlines_and_tabs(self):
        markup = "<format | no_parse>\n\tindented content\n\t\twith tabs\n</format>"
        tokens = tokenize(markup)
        parser = Parser(tokens)
        object = parser.parse()
        correct = {"format": "indented content\n\t\twith tabs"}
        self.assertEqual(correct, object)

    def test_no_parse_multiple_nested_same_name(self):
        markup = "<container | no_parse><container>inner1</container><container>inner2</container></container>"
        tokens = tokenize(markup)
        parser = Parser(tokens)
        object = parser.parse()
        correct = {"container": "<container>inner1</container><container>inner2</container>"}
        self.assertEqual(correct, object)

    def test_no_parse_with_comments_inside(self):
        markup = "<html | no_parse><!-- this is a comment --><p>content</p></html>"
        tokens = tokenize(markup)
        parser = Parser(tokens)
        object = parser.parse()
        # Comments are stripped by tokenizer, so they won't appear in output
        correct = {"html": "<p>content</p>"}
        self.assertEqual(correct, object)

    def test_no_parse_mixed_with_pydantic(self):
        class TestModel(BaseModel):
            normal: str
            raw: str

        markup = "<normal>parsed content</normal><raw | no_parse><inner>raw content</inner></raw>"
        tokens = tokenize(markup)
        parser = Parser(tokens)
        object = parser.parse_to_pydantic(TestModel)
        expected = TestModel(normal="parsed content", raw="<inner>raw content</inner>")
        self.assertEqual(object, expected)

    def test_no_parse_in_repeated_tags(self):
        markup = "<item | no_parse><data>1</data></item><item | no_parse><data>2</data></item>"
        tokens = tokenize(markup)
        parser = Parser(tokens)
        object = parser.parse()
        correct = [{"item": "<data>1</data>"}, {"item": "<data>2</data>"}]
        self.assertEqual(correct, object)

    # Negative test cases - Error conditions
    def test_no_parse_unclosed_tag_error(self):
        markup = "<tag | no_parse><inner>content"  # Missing closing tags
        with self.assertRaises(SyntaxError) as context:
            tokens = tokenize(markup)
            parser = Parser(tokens)
            parser.parse()
        self.assertIn("Unclosed no_parse tag", str(context.exception))

    def test_no_parse_mismatched_closing_tag(self):
        markup = "<tag | no_parse><inner>content</inner></wrong>"
        with self.assertRaises(SyntaxError) as context:
            tokens = tokenize(markup)
            parser = Parser(tokens)
            parser.parse()
        self.assertIn("Unclosed no_parse tag", str(context.exception))

    def test_no_parse_nested_same_tag_unclosed(self):
        markup = "<container | no_parse><container><container>content</container>"  # Missing outer closing
        with self.assertRaises(SyntaxError) as context:
            tokens = tokenize(markup)
            parser = Parser(tokens)
            parser.parse()
        self.assertIn("Unclosed no_parse tag", str(context.exception))

    def test_invalid_filter_syntax_still_works(self):
        # Test that malformed filter syntax doesn't break parsing
        markup = "<tag |><content>test</content></tag>"
        tokens = tokenize(markup)
        parser = Parser(tokens)
        object = parser.parse()
        # Should parse normally since no valid filters found
        correct = {"tag": {"content": "test"}}
        self.assertEqual(correct, object)

    def test_no_parse_empty_filter_name(self):
        markup = "<tag | ><content>test</content></tag>"
        tokens = tokenize(markup)
        parser = Parser(tokens)
        object = parser.parse()
        # Should parse normally since no valid filters found
        correct = {"tag": {"content": "test"}}
        self.assertEqual(correct, object)

    def test_no_parse_filter_with_spaces(self):
        markup = "<tag |  no_parse  ><content>test</content></tag>"
        tokens = tokenize(markup)
        parser = Parser(tokens)
        object = parser.parse()
        correct = {"tag": "<content>test</content>"}
        self.assertEqual(correct, object)

    def test_no_parse_case_sensitivity(self):
        markup = "<tag | NO_PARSE><content>test</content></tag>"
        tokens = tokenize(markup)
        parser = Parser(tokens)
        object = parser.parse()
        # Should parse normally since filter names are case-sensitive
        correct = {"tag": {"content": "test"}}
        self.assertEqual(correct, object)

    def test_no_parse_multiple_pipes(self):
        markup = "<tag | no_parse | invalid><content>test</content></tag>"
        tokens = tokenize(markup)
        parser = Parser(tokens)
        object = parser.parse()
        # Only first pipe section should be processed
        correct = {"tag": "<content>test</content>"}
        self.assertEqual(correct, object)

    def test_no_parse_with_attributes_complex(self):
        markup = '<div | no_parse><input type="text" value="test & more" disabled/><span class="highlight">content</span></div>'
        tokens = tokenize(markup)
        parser = Parser(tokens)
        object = parser.parse()
        # Mixed: self-closing becomes text, proper tags are reconstructed
        correct = {"div": 'input type="text" value="test & more" disabled/><span class="highlight">content</span>'}
        self.assertEqual(correct, object)

    def test_no_parse_very_long_content(self):
        # Tokenizer strips trailing whitespace from text tokens
        long_content = "<p>" + "very long content " * 100
        expected_content = long_content.rstrip() + "</p>"
        markup = f"<large | no_parse>{long_content}</p></large>"
        tokens = tokenize(markup)
        parser = Parser(tokens)
        object = parser.parse()
        correct = {"large": expected_content}
        self.assertEqual(correct, object)

    def test_no_parse_unicode_content(self):
        markup = "<unicode | no_parse><p>Hello 世界! 🌍</p><span>émojis: 🚀✨</span></unicode>"
        tokens = tokenize(markup)
        parser = Parser(tokens)
        object = parser.parse()
        correct = {"unicode": "<p>Hello 世界! 🌍</p><span>émojis: 🚀✨</span>"}
        self.assertEqual(correct, object)

    def test_no_parse_xml_declaration_like(self):
        markup = '<doc | no_parse><?xml version="1.0"?><root>content</root></doc>'
        tokens = tokenize(markup)
        parser = Parser(tokens)
        object = parser.parse()
        correct = {"doc": '<?xml version="1.0"?><root>content</root>'}
        self.assertEqual(correct, object)


if __name__ == "__main__":
    unittest.main()
