# Wasat: Async Gemini Protocol Client Library

Wasat is an asynchronous, object-oriented, fully type-hinted client library for the Gemini Protocol. It is designed to target Python 3.12 and later, relying only on `cryptography` for certificate management and otherwise using the Python standard library.

Features of the library:

- **Asynchronous throughout**: Designed on top of standard `asyncio` with streaming and chunking support.
- **Strictly typed**: Complete type safety utilising modern Python standards, strictly avoiding `Any`.
- **Trust-On-First-Use (TOFU) support**: Secure by default with a built-in file-based trust store and custom verification hooks.
- **Auto redirect handling**: Automatically handles temporary and permanent redirects, protects against redirect loops, and caches permanent redirects.
- **Client authentication**: Native support for client TLS certificates.
- **CLI utility**: Includes a command-line interface out of the box.

## Installation

You can install Wasat in your environment. The recommended tool for modern Python projects is `uv`, but standard `pip` is also fully supported.

### Using uv

To add Wasat to your project as a dependency:

```bash
uv add wasat
```

To install Wasat directly into your active virtual environment:

```bash
uv pip install wasat
```

To run the Wasat command-line interface without installing it globally:

```bash
uvx wasat gemini://geminiprotocol.net/
```

### Using pip

To install Wasat from PyPI using standard packaging tools:

```bash
pip install wasat
```
