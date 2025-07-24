<div align="center">

# 🌌 GravitasML

### *Lightweight Markup Parsing for Python - Perfect for LLMs*
<img src="https://github.com/user-attachments/assets/fefef6b8-4ce0-4918-88aa-86d4582d6044" alt="GravitasML Banner" width="100%">

</div>

---

<p align="center">
  <img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License">
  <img src="https://img.shields.io/pypi/v/gravitasml.svg" alt="PyPI version">
  <img src="https://img.shields.io/pypi/pyversions/gravitasml.svg" alt="Python versions">
  <img src="https://img.shields.io/github/actions/workflow/status/Significant-Gravitas/gravitasml/cicd.yml?branch=main" alt="CI/CD Status">
  <img src="https://img.shields.io/badge/code%20style-black-000000.svg" alt="Code style: black">
</p>

<p align="center">
  <strong>A lightweight Python library for parsing custom markup languages, built and used by <a href="https://github.com/Significant-Gravitas/AutoGPT">AutoGPT</a></strong>
</p>

---

## 🤔 Why use GravitasML?

GravitasML is purpose-built for parsing simple markup structures, particularly **LLM-generated outputs**. 

By design, it excludes XML features that can introduce security risks:
- **No DTD processing** - Prevents billion laughs and quadratic blowup attacks
- **No external entities** - Prevents XXE attacks
- **No entity expansion** - Prevents decompression bombs
- **Simple and predictable** - No namespaces, no attributes, just tags and content

Perfect for:
- Parsing LLM outputs with xml tags
- Simple configuration formats
- Data extraction from controlled markup
- Any scenario where you need safe, simple markup parsing

### 🛡️ Security by Design

GravitasML is immune to [common XML vulnerabilities](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html#python) because it simply doesn't implement the features that enable them:

| Attack Type | GravitasML |
|------------|------------|
| Billion Laughs | ✅ **Safe** (no entity support) |
| Quadratic Blowup | ✅ **Safe** (no entity expansion) |
| External Entity Expansion (XXE) | ✅ **Safe** (no external resources) |
| DTD Retrieval | ✅ **Safe** (no DTD support) |
| Decompression Bomb | ✅ **Safe** (no decompression) |

Perfect for parsing **LLM outputs** and other scenarios where you need simple, secure markup processing.


## ✨ Features

GravitasML transforms custom markup into Python data structures:

- **Simple API** - Parse markup to dictionaries with just a few lines of code
- **Pydantic Integration** - Convert parsed data directly to Pydantic models for validation
- **Nested Structure Support** - Handles nested tags, multiple roots, and repeated elements
- **Tag Normalization** - Automatic whitespace handling and case conversion
- **Error Detection** - Syntax error detection for unmatched or improperly nested tags

## 📦 Installation

```bash
pip install gravitasml
```

Or with Poetry:

```bash
poetry add gravitasml
```

## 🚀 Quick Start

### Basic Usage

```python
from gravitasml.token import tokenize
from gravitasml.parser import Parser

# Parse simple markup
markup = "<name>GravitasML</name>"
tokens = tokenize(markup)
parser = Parser(tokens)
result = parser.parse()

print(result)  # {'name': 'GravitasML'}
```

### Nested Structure Example

```python
from gravitasml.token import tokenize
from gravitasml.parser import Parser

markup = """
<person>
    <name>John Doe</name>
    <contact>
        <email>john@example.com</email>
        <phone>555-0123</phone>
    </contact>
</person>
"""

tokens = tokenize(markup)
result = Parser(tokens).parse()

# Result: {
#     'person': {
#         'name': 'John Doe',
#         'contact': {
#             'email': 'john@example.com',
#             'phone': '555-0123'
#         }
#     }
# }
```

## 🎓 Advanced Usage

### Pydantic Model Integration

Transform your markup directly into validated Pydantic models:

```python
from pydantic import BaseModel
from gravitasml.token import tokenize
from gravitasml.parser import Parser

class Contact(BaseModel):
    email: str
    phone: str

class Person(BaseModel):
    name: str
    contact: Contact

markup = """
<person>
    <name>Jane Smith</name>
    <contact>
        <email>jane@example.com</email>
        <phone>555-9876</phone>
    </contact>
</person>
"""

tokens = tokenize(markup)
parser = Parser(tokens)
person = parser.parse_to_pydantic(Person)

print(person.name)  # Jane Smith
print(person.contact.email)  # jane@example.com
```

### Handling Repeated Tags

GravitasML automatically converts repeated tags into lists:

```python
from gravitasml.token import tokenize
from gravitasml.parser import Parser

markup = "<tag><a>value1</a><a>value2</a></tag>"
tokens = tokenize(markup)
result = Parser(tokens).parse()
# Result: {'tag': [{'a': 'value1'}, {'a': 'value2'}]}

# Multiple root tags with the same name also become a list
markup2 = "<tag>content1</tag><tag>content2</tag>"
tokens2 = tokenize(markup2)
result2 = Parser(tokens2).parse()
# Result: [{'tag': 'content1'}, {'tag': 'content2'}]
```

### Tag Name Normalization

Tag names are automatically normalized - spaces become underscores and names are lowercased:

```python
from gravitasml.token import tokenize
from gravitasml.parser import Parser

# Spaces in tag names are converted to underscores
markup = "<User Profile><First Name>Alice</First Name></User Profile>"
tokens = tokenize(markup)
result = Parser(tokens).parse()
# Result: {'user_profile': {'first_name': 'Alice'}}
```

## 🏗️ Architecture

GravitasML uses a two-stage parsing approach:

1. **Tokenization** (`gravitasml.token`) - Converts raw markup into a stream of tokens
2. **Parsing** (`gravitasml.parser`) - Builds a tree structure and converts to Python objects

## 🧪 Testing

GravitasML comes with a test suite. To run the tests, execute the following command:

```bash
python -m unittest discover -v
```

## 📊 Dependencies

GravitasML has minimal dependencies:

- Python 3.10, 3.11, or 3.12 (tested in CI)
- Pydantic 2.x (for model validation features)
- Black (development dependency for code formatting)
- Pytest (development dependency)

## 🤝 Contributing

We welcome contributions! GravitasML uses:

- **Poetry** for dependency management
- **Black** for code formatting
- **GitHub Actions** for CI/CD
- **unittest** for testing

To contribute:

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes and add tests
4. Ensure all tests pass and code is formatted with Black
5. Commit your changes (`git commit -m 'Add amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

See our [CI/CD workflow](.github/workflows/cicd.yml) for the automated checks your PR must pass.

## 📝 Current Limitations

GravitasML is designed for simplicity. It currently does not support:

- XML namespaces or schema validation
- Tag attributes (e.g., `<tag attr="value">`)
- Processing instructions or CDATA sections
- Writing/generating markup (parsing only)
- Streaming parsing for very large documents
- Self-closing tags (e.g., `<tag />`)

These limitations are intentional to keep the library focused and easy to use. If you need these features, consider using Python's built-in `xml.etree.ElementTree` or third-party libraries like `lxml`.

## 🎯 Philosophy

GravitasML is built on the principle that **not every markup parsing task needs the complexity of full XML processing**. Sometimes you just want to convert simple markup to Python dictionaries without the overhead of namespaces, DTDs, or complex validation rules.

## 📄 License

GravitasML is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

Built by the [AutoGPT Team](https://github.com/Significant-Gravitas/AutoGPT) and used in the AutoGPT project.

---

<p align="center">
  <i>Simple markup parsing for modern Python applications.</i>
</p>
