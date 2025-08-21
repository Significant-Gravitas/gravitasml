from typing import Any, Type, Union
from gravitasml.token import Token, tokenize
from pydantic import BaseModel, ValidationError


def parse_markup(markup: str) -> dict[str, Any] | list:
    """
    Convenience function to parse markup with full no_parse filter support.
    
    Args:
        markup (str): The markup string to parse
        
    Returns:
        dict[str, Any] | list: The parsed data
    """
    tokens = tokenize(markup)
    parser = Parser(tokens, markup)
    return parser.parse()


class Node:
    """
    A class representing a node in a tree structure.

    Attributes:
    - tag (str): The tag associated with the node.
    - children (list): A list of child nodes.
    - parent (Node): The parent node.
    - value (str): The value associated with the node.
    """

    def __init__(self, tag):
        self.tag = tag
        self.children = []
        self.parent = None
        self.value = ""

    def add(self, child):
        self.children.append(child)
        child.parent = self

    def to_dict(self):
        if self.children:
            # If theres only one kid, treat it as an entry in the dict
            if len(self.children) == 1:
                return {self.tag: self.children[0].to_dict()}
            # if theres multiple kids, get the keys (tags)
            keys = [child.tag for child in self.children]

            # check if the kids are unique values if they can be collapsed or not; all unique means yes
            if len(set(keys)) == len(keys):
                # No duplicate keys
                result = {}
                for child in self.children:
                    result.update(child.to_dict())
                return {self.tag: result}

            else:
                # Duplicate keys found
                return {self.tag: [child.to_dict() for child in self.children]}
        else:
            return {self.tag: self.value}


class List:
    """
    A class representing a list of children nodes.

    Attributes:
    - children (list): A list of child nodes.
    """

    def __init__(self):
        self.children = []

    def add(self, child):
        self.children.append(child)
        child.parent = self
    
    def add_text(self, text):
        """Add text content - currently ignored for standalone text at root level."""
        # For now, we'll ignore standalone text at root level
        # This prevents errors when self-closing tags are not recognized
        pass

    def to_dict(self):
        """
        Converts the list and its children to a dictionary.

        Returns:
        - dict or list: A dictionary or list representation of the list and its children.
        """
        if len(self.children) == 1:
            return self.children[0].to_dict()

        keys = [child.tag for child in self.children]
        if len(set(keys)) == len(keys):
            # No duplicate keys
            result = {}
            for child in self.children:
                result.update(child.to_dict())
            return result

        else:
            # Duplicate keys found
            return [child.to_dict() for child in self.children]


class Parser:
    """
    A parser for HTML-like markup language with filter support.

    Args:
        tokens (list[Token]): A list of tokens to be parsed.
        original_markup (str, optional): The original markup string for precise content extraction.

    Attributes:
        root (List): The root node of the parsed tree.
        current (Node): The current node being parsed.
        tokens (list[Token]): The list of tokens to be parsed.
        stack (list[str]): A stack to keep track of open tags.
        original_markup (str): The original markup string.

    Supported Filters:
        no_parse: Prevents recursive parsing of content, preserving it as raw string.
                 Usage: <tag | no_parse>content</tag>

    Methods:
        parse() -> dict[str, Any] | list: Parses the tokens and returns a dictionary or list.
        parse_to_pydantic(model: Type[BaseModel]) -> BaseModel | list[BaseModel]: Parses the tokens and returns a Pydantic model instance or a list of instances.
    """

    def __init__(self, tokens: list[Token], original_markup: str = ""):
        self.root = List()
        self.current = self.root
        self.tokens = tokens
        self.stack = []
        self.original_markup = original_markup

    def parse(self) -> dict[str, Any] | list:
        """
        Parses the tokens and returns a dictionary or list.
        
        Handles filter processing for TAG_OPEN tokens. Currently supports:
        - no_parse filter: Preserves content as raw string without recursive parsing

        Returns:
            dict[str, Any] | list: The parsed data.
        """
        i = 0
        while i < len(self.tokens):
            t = self.tokens[i]
            
            if t.type == "TEXT":
                if isinstance(self.current, List):
                    self.current.add_text(t.value)  # type: ignore
                elif isinstance(self.current, Node):
                    self.current.value += t.value  # type: Node
                    
            elif t.type == "TAG_OPEN":
                # Check if this tag has a no_parse filter
                if "no_parse" in t.filters:
                    # Handle no_parse tag: collect all content until matching close tag
                    i = self._handle_no_parse_tag(i)
                else:
                    # Normal tag processing
                    self.stack.append(t.value)
                    child = Node(t.value)
                    self.current.add(child)
                    self.current = child

            elif t.type == "TAG_CLOSE":
                if not self.stack:
                    raise Exception("Unmatched closing tag")
                expected = self.stack.pop()
                if t.value != expected:
                    raise SyntaxError(f"Mismatched tags: {expected} and {t.value}")
                if self.current.parent:  # type: ignore
                    self.current = self.current.parent  # type: ignore
                else:
                    raise Exception("Unmatched closing tag")
            
            i += 1

        if self.stack:
            raise SyntaxError("Unclosed tag")
        return self.root.to_dict()

    def _handle_no_parse_tag(self, start_index: int) -> int:
        """
        Handle a tag with no_parse filter by collecting all content until matching close tag.
        
        Args:
            start_index: Index of the opening tag token
            
        Returns:
            Index of the closing tag token
        """
        open_token = self.tokens[start_index]
        tag_name = open_token.value
        
        # Create the node
        child = Node(tag_name)
        self.current.add(child)
        
        # Find matching close tag and track depth for nested same-name tags
        i = start_index + 1
        depth = 1
        
        while i < len(self.tokens) and depth > 0:
            token = self.tokens[i]
            
            if token.type == "TAG_OPEN" and token.value == tag_name:
                depth += 1
            elif token.type == "TAG_CLOSE" and token.value == tag_name:
                depth -= 1
                if depth == 0:
                    # Found our matching closing tag
                    break
            
            i += 1
        
        if depth > 0:
            raise SyntaxError(f"Unclosed no_parse tag: {tag_name}")
        
        # Extract raw content using original markup if available
        if self.original_markup:
            raw_content = self._extract_raw_content_from_markup(start_index, i)
        else:
            # Fallback: reconstruct from tokens (less accurate whitespace)
            raw_content = self._reconstruct_content_from_tokens(start_index, i, tag_name)
        
        # Set the raw content as the node's value
        child.value = raw_content
        
        # Return the index of the closing tag
        return i
    
    def _extract_raw_content_from_markup(self, open_index: int, close_index: int) -> str:
        """Extract exact content from original markup using token positions."""
        import re
        
        open_token = self.tokens[open_index]
        close_token = self.tokens[close_index]
        
        # Find the end of the opening tag in original markup
        start_search = open_token.column
        remaining_markup = self.original_markup[start_search:]
        match = re.search(r'>', remaining_markup)
        if match:
            content_start = start_search + match.end()
        else:
            content_start = start_search
        
        # Find the start of the closing tag
        content_end = close_token.column
        
        # Extract exact content preserving whitespace
        if content_start < content_end:
            return self.original_markup[content_start:content_end]
        else:
            return ""
    
    def _reconstruct_content_from_tokens(self, start_index: int, end_index: int, tag_name: str) -> str:
        """Fallback: reconstruct content from tokens (less accurate for whitespace)."""
        raw_content = ""
        depth = 1
        
        for i in range(start_index + 1, end_index):
            token = self.tokens[i]
            
            if token.type == "TAG_OPEN" and token.value == tag_name:
                depth += 1
                original_tag = self._reconstruct_original_tag(token)
                raw_content += original_tag
            elif token.type == "TAG_CLOSE" and token.value == tag_name:
                depth -= 1
                if depth > 0:
                    raw_content += f"</{token.value}>"
            elif token.type == "TEXT":
                raw_content += token.value
            elif token.type == "TAG_OPEN":
                original_tag = self._reconstruct_original_tag(token)
                raw_content += original_tag
            elif token.type == "TAG_CLOSE":
                raw_content += f"</{token.value}>"
        
        return raw_content
    
    def _reconstruct_original_tag(self, token: Token) -> str:
        """Reconstruct original tag format from processed token."""
        # Convert back from processed format
        tag_value = token.value
        # Convert underscores back to spaces
        tag_value = tag_value.replace("_", " ")
        return f"<{tag_value}>"

    def parse_to_pydantic(self, model: Type[BaseModel]) -> BaseModel | list[BaseModel]:
        """
        Parses the tokens and returns a Pydantic model instance or a list of instances.

        Args:
            model (Type[BaseModel]): The Pydantic model to use for parsing.

        Returns:
            BaseModel | list[BaseModel]: The parsed data as a Pydantic model instance or a list of instances.
        """
        obj: Union[dict, list] = self.parse()

        if isinstance(obj, dict):
            try:
                return model(**obj)
            except ValidationError as e:
                raise ValueError(f"Validation error for dict: {e}") from e

        elif isinstance(obj, list):
            try:
                return [model(**item) for item in obj]
            except ValidationError as e:
                raise ValueError(f"Validation error for list: {e}") from e

        else:
            raise ValueError(f"Unknown object type: {type(obj)}")
