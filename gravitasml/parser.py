from typing import Any, Type, Union
from gravitasml.token import Token
from pydantic import BaseModel, ValidationError


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

    Attributes:
        root (List): The root node of the parsed tree.
        current (Node): The current node being parsed.
        tokens (list[Token]): The list of tokens to be parsed.
        stack (list[str]): A stack to keep track of open tags.

    Supported Filters:
        no_parse: Prevents recursive parsing of content, preserving it as raw string.
                 Usage: <tag | no_parse>content</tag>

    Methods:
        parse() -> dict[str, Any] | list: Parses the tokens and returns a dictionary or list.
        parse_to_pydantic(model: Type[BaseModel]) -> BaseModel | list[BaseModel]: Parses the tokens and returns a Pydantic model instance or a list of instances.
    """

    def __init__(self, tokens: list[Token]):
        self.root = List()
        self.current = self.root
        self.tokens = tokens
        self.stack = []

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
        
        # We need to reconstruct the original markup from the token positions
        # Find the original markup for this section
        i = start_index + 1
        depth = 1
        start_pos = None
        end_pos = None
        
        # Find the positions in original markup
        while i < len(self.tokens) and depth > 0:
            token = self.tokens[i]
            
            if start_pos is None:
                start_pos = token.column
            
            if token.type == "TAG_OPEN" and token.value == tag_name:
                depth += 1
            elif token.type == "TAG_CLOSE" and token.value == tag_name:
                depth -= 1
                if depth == 0:
                    # This is our closing tag - find where it ends
                    end_pos = token.column
            
            i += 1
        
        if depth > 0:
            raise SyntaxError(f"Unclosed no_parse tag: {tag_name}")
        
        # For now, let's reconstruct from tokens but preserve original format
        raw_content = ""
        i = start_index + 1
        depth = 1
        
        while i < len(self.tokens) and depth > 0:
            token = self.tokens[i]
            
            if token.type == "TAG_OPEN" and token.value == tag_name:
                depth += 1
                # Reconstruct original tag format
                original_tag = self._reconstruct_original_tag(token)
                raw_content += original_tag
            elif token.type == "TAG_CLOSE" and token.value == tag_name:
                depth -= 1
                if depth > 0:
                    raw_content += f"</{token.value}>"
            elif token.type == "TEXT":
                raw_content += token.value
            elif token.type == "TAG_OPEN":
                # Reconstruct original tag format
                original_tag = self._reconstruct_original_tag(token)
                raw_content += original_tag
            elif token.type == "TAG_CLOSE":
                raw_content += f"</{token.value}>"
            
            i += 1
        
        # Set the raw content as the node's value
        child.value = raw_content
        
        # Return the index of the closing tag
        return i - 1
    
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
