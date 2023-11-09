
# GravitasML

GravitasML is a lightweight Python library for parsing custom markup languages. It provides a simple and intuitive API to convert markup into Python objects or dictionaries.

## Features

- Easy-to-use parser for custom markup languages.
- Convert markup directly to Python dictionaries.
- Handles nested and multiple root tags.
- Customizable tag names with automatic whitespace conversion.
- Syntax error detection for unmatched or improperly nested tags.

## Installation

To install GravitasML, use pip as follows:

```bash
pip install gravitasml
```

## Quick Start

Here's a quick example to get you started:

```python
from gravitasml.token import tokenize
from gravitasml.parser import Parser

markup = "<tag1><tag2>content</tag2></tag1>"
tokens = tokenize(markup)
parser = Parser(tokens)
obj = parser.parse()

print(obj)  # Output: {'tag1': {'tag2': 'content'}}
```

## Limitations

GravitasML is designed to be simple and intuitive, but there are some limitations to be aware of:

- It does not support XML namespaces or schema validation.
- It does not handle processing instructions or CDATA sections found in XML.
- Currently, there is no support for attributes within tags; only tag names and content are parsed.
- It does not provide functionality to write or generate markup, only to parse it.
- GravitasML is not optimized for extremely large documents or streaming parsing.

## Documentation

For detailed usage and documentation, please refer to the `docs` directory in this repository.

## Tests

GravitasML comes with a comprehensive test suite. To run the tests, execute the following command:

```bash
python -m unittest discover -v
```

## Contributing

We welcome contributions from the community. If you'd like to contribute, please fork the repository and submit a pull request.

## License

GravitasML is licensed under the MIT License - see the LICENSE file for details.
