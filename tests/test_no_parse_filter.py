import unittest
from pydantic import BaseModel

from gravitasml.token import tokenize
from gravitasml.parser import Parser, parse_markup, NoParseError


class TestNoParseFilter(unittest.TestCase):
    """Comprehensive tests for the no_parse filter functionality."""
    
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
    
    def test_no_parse_mixed_with_normal_tags(self):
        """Test no_parse filter mixed with normal tag parsing"""
        markup = '<root><normal>parsed</normal><no_parse | no_parse><inner>not parsed</inner></no_parse></root>'
        result = parse_markup(markup)
        expected = {'root': {'normal': 'parsed', 'no_parse': '<inner>not parsed</inner>'}}
        self.assertEqual(expected, result)
    
    def test_no_parse_with_multiple_filters(self):
        """Test multiple filters including no_parse"""
        markup = '<tag | no_parse other_filter><content>test</content></tag>'
        result = parse_markup(markup)
        expected = {'tag': '<content>test</content>'}
        self.assertEqual(expected, result)
    
    def test_no_parse_deeply_nested(self):
        """Test deeply nested content preservation"""
        markup = '<outer | no_parse><level1><level2><level3>deep content</level3></level2></level1></outer>'
        result = parse_markup(markup)
        expected = {'outer': '<level1><level2><level3>deep content</level3></level2></level1>'}
        self.assertEqual(expected, result)
    
    def test_no_parse_with_special_characters(self):
        """Test no_parse with special characters and symbols"""
        markup = '<code | no_parse>function test() { return "hello & goodbye"; }</code>'
        result = parse_markup(markup)
        expected = {'code': 'function test() { return "hello & goodbye"; }'}
        self.assertEqual(expected, result)
    
    def test_no_parse_unicode_content(self):
        """Test no_parse with Unicode characters"""
        markup = '<unicode | no_parse><p>Hello 世界! 🌍</p><span>émojis: 🚀✨</span></unicode>'
        result = parse_markup(markup)
        expected = {'unicode': '<p>Hello 世界! 🌍</p><span>émojis: 🚀✨</span>'}
        self.assertEqual(expected, result)
    
    def test_no_parse_with_newlines_and_tabs(self):
        """Test whitespace preservation with newlines and tabs"""
        markup = '<format | no_parse>\n\tindented content\n\t\twith tabs\n</format>'
        result = parse_markup(markup)
        expected = {'format': '\n\tindented content\n\t\twith tabs\n'}
        self.assertEqual(expected, result)
    
    def test_no_parse_multiple_root_tags(self):
        """Test no_parse filter with multiple root tags"""
        markup = '<tag | no_parse><inner>content1</inner></tag><tag | no_parse><inner>content2</inner></tag>'
        result = parse_markup(markup)
        expected = [{'tag': '<inner>content1</inner>'}, {'tag': '<inner>content2</inner>'}]
        self.assertEqual(expected, result)
    
    def test_no_parse_with_pydantic_integration(self):
        """Test no_parse filter with Pydantic model parsing"""
        class TestModel(BaseModel):
            normal: str
            raw: str

        markup = '<normal>parsed content</normal><raw | no_parse><inner>raw content</inner></raw>'
        tokens = tokenize(markup)
        parser = Parser(tokens, markup)
        result = parser.parse_to_pydantic(TestModel)
        expected = TestModel(normal='parsed content', raw='<inner>raw content</inner>')
        self.assertEqual(expected, result)
    
    # Error handling tests
    def test_no_parse_unclosed_tag_error(self):
        """Test that unclosed no_parse tags raise appropriate errors"""
        markup = '<tag | no_parse><inner>content'  # Missing closing tags
        with self.assertRaises(NoParseError) as context:
            parse_markup(markup)
        self.assertIn('Unclosed no_parse tag', str(context.exception))
    
    def test_no_parse_mismatched_closing_tag(self):
        """Test error handling for mismatched closing tags"""
        markup = '<tag | no_parse><inner>content</inner></wrong>'
        with self.assertRaises(NoParseError) as context:
            parse_markup(markup)
        self.assertIn('Unclosed no_parse tag', str(context.exception))
    
    # Backward compatibility tests
    def test_backward_compatibility_token_only_parsing(self):
        """Test that token-only parsing still works (fallback mode)"""
        markup = '<tag | no_parse><inner>content</inner></tag>'
        tokens = tokenize(markup)
        parser = Parser(tokens)  # No original markup provided
        result = parser.parse()
        # Should work but with less precise whitespace handling
        expected = {'tag': '<inner>content</inner>'}
        self.assertEqual(expected, result)
    
    def test_filter_syntax_edge_cases(self):
        """Test edge cases in filter syntax parsing"""
        test_cases = [
            ('<tag |><content>test</content></tag>', {'tag': {'content': 'test'}}),  # Empty filter
            ('<tag | ><content>test</content></tag>', {'tag': {'content': 'test'}}),  # Space only
            ('<tag |  no_parse  ><content>test</content></tag>', {'tag': '<content>test</content>'}),  # Extra spaces
            ('<tag | NO_PARSE><content>test</content></tag>', {'tag': {'content': 'test'}}),  # Case sensitivity
        ]
        
        for markup, expected in test_cases:
            with self.subTest(markup=markup):
                result = parse_markup(markup)
                self.assertEqual(expected, result)
    
    def test_no_parse_performance_large_content(self):
        """Test no_parse with large content blocks"""
        large_content = '<p>' + 'Large content block ' * 1000 + '</p>'
        markup = f'<container | no_parse>{large_content}</container>'
        result = parse_markup(markup)
        expected = {'container': large_content}
        self.assertEqual(expected, result)


if __name__ == '__main__':
    unittest.main()