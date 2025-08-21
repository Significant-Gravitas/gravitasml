from typing import Any, Type, Union
from gravitasml.token import Token, tokenize
from pydantic import BaseModel, ValidationError


def parse_markup(markup: str) -> dict[str, Any] | list:
    """
    Helper function to parse markup with full no_parse filter support.
    
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
    A parser for HTML-like markup language.

    Args:
        tokens (list[Token]): A list of tokens to be parsed.
        original_markup (str, optional): The original markup string for raw content extraction.

    Attributes:
        root (List): The root node of the parsed tree.
        current (Node): The current node being parsed.
        tokens (list[Token]): The list of tokens to be parsed.
        stack (list[str]): A stack to keep track of open tags.
        original_markup (str): The original markup string.

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

        Returns:
            dict[str, Any] | list: The parsed data.
        """
        i = 0
        while i < len(self.tokens):
            t = self.tokens[i]
            if t.type == "TEXT":
                if isinstance(self.current, List):
                    # Handle text at root level - could be from invalid markup
                    # For now, we'll ignore standalone text at root level
                    # This prevents errors when self-closing tags are not recognized
                    pass
                elif isinstance(self.current, Node):
                    self.current.value += t.value  # type: Node
            elif t.type == "TAG_OPEN":
                self.stack.append(t.value)

                child = Node(t.value)
                self.current.add(child)
                self.current = child
                
                # Check for no_parse filter
                if "no_parse" in t.filters:
                    # Find the matching close tag and extract raw content
                    tag_name = t.value
                    open_count = 1
                    i += 1  # Move to next token
                    start_pos = None
                    end_pos = None
                    
                    # Find the position right after the opening tag in original markup
                    if self.original_markup:
                        # Use the current token's position information to find where this tag ends
                        # We need to find where this specific opening tag ends
                        # Look for the closing > after the current token's position
                        import re
                        # Start looking from this token's column position
                        start_search = t.column
                        remaining_markup = self.original_markup[start_search:]
                        match = re.search(r'>', remaining_markup)
                        if match:
                            start_pos = start_search + match.end()
                    
                    while i < len(self.tokens) and open_count > 0:
                        current_token = self.tokens[i]
                        
                        if current_token.type == "TAG_OPEN" and current_token.value == tag_name:
                            open_count += 1
                        elif current_token.type == "TAG_CLOSE" and current_token.value == tag_name:
                            open_count -= 1
                            if open_count == 0 and self.original_markup:
                                # This is our matching closing tag - use its position
                                end_pos = current_token.column
                        i += 1
                    
                    # Check if we found a matching closing tag
                    if open_count > 0:
                        # No matching closing tag found - this is an unclosed tag
                        raise SyntaxError("Unclosed tag")
                    
                    # Extract raw content from original markup if we have positions
                    if self.original_markup and start_pos is not None and end_pos is not None:
                        raw_content = self.original_markup[start_pos:end_pos]
                    else:
                        # Fallback to empty string if we can't extract
                        raw_content = ""
                    
                    # Set the raw content as the node's value
                    self.current.value = raw_content
                    
                    # Move back to parent
                    if self.current.parent:  # type: ignore
                        self.current = self.current.parent  # type: ignore
                    else:
                        raise Exception("Unmatched closing tag")
                    
                    # Pop from stack since we processed the close tag
                    self.stack.pop()
                    
                    continue  # Skip the normal increment

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
