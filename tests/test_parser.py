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

    def test_text_outside_root_raises_value_error(self):
        markup = "<tag>content</tag> trailing"
        tokens = tokenize(markup)
        parser = Parser(tokens)
        with self.assertRaisesRegex(ValueError, "Text outside of a tag"):
            parser.parse()

    def test_text_only_document_raises_value_error(self):
        markup = "just dangling text"
        tokens = tokenize(markup)
        parser = Parser(tokens)
        with self.assertRaisesRegex(ValueError, "Text outside of a tag"):
            parser.parse()

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


if __name__ == "__main__":
    unittest.main()
