import re


class Token:
    """
    A class representing a token in a programming language.

    Attributes:
        type (str): The type of the token.
        value (Any): The value of the token.
        line_num (int): The line number where the token appears in the source code.
        column (int): The column number where the token appears in the source code.
    """

    def __init__(self, token_type, value, line_num, column: int):
        self.type = token_type
        self.value = value
        self.line_num = line_num
        self.column = column

    def __repr__(self):
        return (
            f"Token({self.type!r}, {self.value!r}, {self.line_num!r}, {self.column!r})"
        )

    def __str__(self):
        return f"{self.type}({self.value})"

    def __eq__(self, other):
        if isinstance(other, Token):
            return (
                self.type == other.type
                and self.value == other.value
                and self.line_num == other.line_num
                and self.column == other.column
            )
        return False


def tokenize(markup: str) -> list[Token]:
    """
    Tokenizes the given markup string into a list of tokens.

    Args:
        markup (str): The markup string to tokenize.

    Returns:
        list[Token]: A list of Token objects representing the tokens in the markup string.
    """
    line_num = 1
    line_start = 0
    tokens: list[Token] = []
    token_specification = [
        ("ESCAPE", r"\\."),
        ("COMMENT", r"<!--.*?-->"),  # Comment
        ("TAG_OPEN", r"<\s*[^>/]+\s*>"),
        ("TAG_CLOSE", r"</\s*[^>]+\s*>"),
        ("TEXT", r"[^<]+(?!\\.)"),  # Text
    ]
    token_regex = "|".join(f"(?P<{pair[0]}>{pair[1]})" for pair in token_specification)

    for mo in re.finditer(
        token_regex, markup, re.DOTALL
    ):  # re.DOTALL to allow '.' to match newline
        kind = mo.lastgroup
        value = mo.group()
        if kind == "COMMENT":
            # Comments are ignored, no need to add them to the token list
            continue
        elif kind == "ESCAPE":
            # Instead of skipping, you append the escaped value as a text token
            tokens.append(Token("ESCAPE", value, line_num, mo.start() - line_start))
            continue
        elif kind == "TEXT":
            value = value.strip()
        # Cleanup the OPEN and CLOSE
        elif kind == "TAG_OPEN" or kind == "TAG_CLOSE":
            # Drop the </> from the outside, raise if not there
            if kind == "TAG_OPEN" and value[0] == "<" and value[-1] == ">":
                value = value[1:-1]
            elif (
                kind == "TAG_CLOSE"
                and value[0] == "<"
                and value[1] == "/"
                and value[-1] == ">"
            ):
                value = value[2:-1]
            else:
                print(value)
                raise ValueError("Value must start with '<' and end with '>'")
            # drop extra whitespace on outside
            value = value.strip()
            # convert whitespace to _
            value = re.sub(r"\s+", "_", value)
            # convert to lower case
            value = value.lower()

        column = mo.start() - line_start
        if value == "\n":
            line_start = mo.end()
            line_num += 1
            continue

        # dont populate empty tokens (like new lines)
        if value:
            tokens.append(Token(kind, value, line_num, column))
        continue

    return tokens
