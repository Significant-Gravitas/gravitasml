import unittest

from gravitasml.token import tokenize
from gravitasml.parser import Parser, parse_markup


class TestNoParseFilter(unittest.TestCase):
    
    def test_basic_no_parse_filter(self):
        """Test basic no_parse filter functionality"""
        markup = '<tag | no_parse><inner><content>anything</content></inner></tag>'
        result = parse_markup(markup)
        expected = {'tag': '<inner><content>anything</content></inner>'}
        self.assertEqual(expected, result)
    
    def test_no_parse_with_nested_same_tag(self):
        """Test no_parse filter with nested tags of the same name"""
        markup = '<tag | no_parse><tag>nested</tag><other>stuff</other></tag>'
        result = parse_markup(markup)
        expected = {'tag': '<tag>nested</tag><other>stuff</other>'}
        self.assertEqual(expected, result)
    
    def test_no_parse_with_multiple_nested(self):
        """Test no_parse filter with multiple nested same-name tags"""
        markup = '<tag | no_parse><tag><tag>deep</tag></tag><content>more</content></tag>'
        result = parse_markup(markup)
        expected = {'tag': '<tag><tag>deep</tag></tag><content>more</content>'}
        self.assertEqual(expected, result)
    
    def test_no_parse_preserves_exact_content(self):
        """Test that no_parse preserves exact inner content including whitespace"""
        markup = '<tag | no_parse>  <inner>  content  </inner>  </tag>'
        result = parse_markup(markup)
        expected = {'tag': '  <inner>  content  </inner>  '}
        self.assertEqual(expected, result)
    
    def test_no_parse_with_empty_content(self):
        """Test no_parse filter with empty content"""
        markup = '<tag | no_parse></tag>'
        result = parse_markup(markup)
        expected = {'tag': ''}
        self.assertEqual(expected, result)
    
    def test_no_parse_with_text_only(self):
        """Test no_parse filter with plain text content"""
        markup = '<tag | no_parse>just plain text</tag>'
        result = parse_markup(markup)
        expected = {'tag': 'just plain text'}
        self.assertEqual(expected, result)
    
    def test_no_parse_multiple_root_tags(self):
        """Test no_parse filter with multiple root tags"""
        markup = '<tag | no_parse><inner>content1</inner></tag><tag | no_parse><inner>content2</inner></tag>'
        result = parse_markup(markup)
        expected = [{'tag': '<inner>content1</inner>'}, {'tag': '<inner>content2</inner>'}]
        self.assertEqual(expected, result)
    
    def test_no_parse_mixed_with_normal_tags(self):
        """Test no_parse filter mixed with normal tag parsing"""
        markup = '<root><normal>parsed</normal><no_parse | no_parse><inner>not parsed</inner></no_parse></root>'
        result = parse_markup(markup)
        expected = {'root': {'normal': 'parsed', 'no_parse': '<inner>not parsed</inner>'}}
        self.assertEqual(expected, result)
    
    def test_no_parse_with_complex_html_like_content(self):
        """Test no_parse filter with complex HTML-like content"""
        markup = '<template | no_parse><div class="container"><p>Hello <strong>world</strong>!</p><ul><li>Item 1</li><li>Item 2</li></ul></div></template>'
        result = parse_markup(markup)
        expected = {'template': '<div class="container"><p>Hello <strong>world</strong>!</p><ul><li>Item 1</li><li>Item 2</li></ul></div>'}
        self.assertEqual(expected, result)
    
    def test_no_parse_with_escaped_characters(self):
        """Test no_parse filter with escaped characters"""
        markup = r'<tag | no_parse>content with \< and \> characters</tag>'
        result = parse_markup(markup)
        expected = {'tag': r'content with \< and \> characters'}
        self.assertEqual(expected, result)
    
    def test_multiple_filters_with_no_parse(self):
        """Test multiple filters including no_parse"""
        markup = '<tag | no_parse | other_filter>content</tag>'
        result = parse_markup(markup)
        expected = {'tag': 'content'}
        self.assertEqual(expected, result)
    
    def test_filter_syntax_tokenization(self):
        """Test that filter syntax is properly tokenized"""
        markup = '<tag | no_parse>content</tag>'
        tokens = tokenize(markup)
        
        # Check that TAG_OPEN token has the correct filters
        tag_open_token = None
        for token in tokens:
            if token.type == "TAG_OPEN":
                tag_open_token = token
                break
        
        self.assertIsNotNone(tag_open_token)
        self.assertEqual(tag_open_token.value, "tag")
        self.assertEqual(tag_open_token.filters, ["no_parse"])
    
    def test_backward_compatibility_no_filters(self):
        """Test that tags without filters work exactly as before"""
        markup = '<tag><inner>content</inner></tag>'
        result = parse_markup(markup)
        expected = {'tag': {'inner': 'content'}}
        self.assertEqual(expected, result)
        
        # Also test the original method still works
        tokens = tokenize(markup)
        parser = Parser(tokens)
        result2 = parser.parse()
        self.assertEqual(expected, result2)
        
        # Check that tokens without filters have empty filters list
        for token in tokens:
            if token.type == "TAG_OPEN":
                self.assertEqual(token.filters, [])
    
    def test_self_closing_tag_with_no_parse_filter(self):
        """Test that self-closing tags with no_parse filter are not recognized as tags"""
        # Self-closing tags are not supported by the current grammar
        # They should be treated as text, which gets ignored at root level
        markup = '<tag | no_parse />content'
        result = parse_markup(markup)
        # Since <tag | no_parse /> is not recognized as a tag, the content becomes
        # standalone text which is ignored, resulting in an empty dict
        expected = {}
        self.assertEqual(expected, result)
    
    def test_self_closing_tag_without_filter(self):
        """Test that self-closing tags are not recognized as valid tags (baseline behavior)"""
        markup = '<tag />content'
        result = parse_markup(markup)
        # Self-closing tags should not be recognized, content should be ignored
        expected = {}
        self.assertEqual(expected, result)
    
    def test_unmatched_opening_tag_with_no_parse_filter(self):
        """Test that unmatched opening tags with no_parse filter raise an error"""
        markup = '<tag | no_parse>some content'
        with self.assertRaises(SyntaxError) as context:
            parse_markup(markup)
        self.assertIn("Unclosed tag", str(context.exception))
    
    def test_unmatched_opening_tag_without_filter(self):
        """Test that unmatched opening tags raise an error (baseline behavior)"""
        markup = '<tag>some content'
        with self.assertRaises(SyntaxError) as context:
            parse_markup(markup)
        self.assertIn("Unclosed tag", str(context.exception))
    
    def test_mismatched_tags_with_no_parse_filter(self):
        """Test that mismatched tags with no_parse filter raise an error"""
        markup = '<tag | no_parse>content</othertag>'
        with self.assertRaises(SyntaxError) as context:
            parse_markup(markup)
        # With no_parse filter, mismatched tags are detected as unclosed tags
        # because the no_parse logic looks for the specific matching tag
        self.assertIn("Unclosed tag", str(context.exception))
    
    def test_unmatched_closing_tag(self):
        """Test that unmatched closing tags raise an error"""
        markup = '</tag>'
        with self.assertRaises(Exception) as context:
            parse_markup(markup)
        # Should raise an error about unmatched closing tag
        self.assertIn("Unmatched closing tag", str(context.exception))


if __name__ == "__main__":
    unittest.main()