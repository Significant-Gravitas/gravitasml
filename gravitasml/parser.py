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

    def add_text(self, token: Token):
        """
        Handles raw text when the parser is not currently inside a node.
        """
        text = token.value
        if not text or text.isspace():
            return
        raise ValueError(
            f"Text outside of a tag is unsupported at line {token.line_num}, column {token.column}"
        )

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

    Attributes:
        root (List): The root node of the parsed tree.
        current (Node): The current node being parsed.
        tokens (list[Token]): The list of tokens to be parsed.
        stack (list[str]): A stack to keep track of open tags.

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

        Returns:
            dict[str, Any] | list: The parsed data.
        """
        for t in self.tokens:
            if t.type == "TEXT":
                if isinstance(self.current, List):
                    self.current.add_text(t)
                elif isinstance(self.current, Node):
                    self.current.value += t.value  # type: Node
            elif t.type == "TAG_OPEN":
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
