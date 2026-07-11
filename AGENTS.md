# Agent Instructions for Wasat

## Codebase Architecture

All source code lives in [src/wasat/](src/wasat/). Key modules and their responsibilities:

| Module | Responsibility |
|---|---|
| [`__init__.py`](src/wasat/__init__.py) | Library entry point. Exposes public classes (`Client`, `Response`, `StatusCode`, `GeminiURI`, `TrustStore`, `FileTrustStore`, `ClientCertificateStore`, `FileClientCertificateStore`), types/callbacks (`ClientCertCallback`), helper functions (`generate_self_signed_cert`), and exceptions, while keeping internal details hidden. |
| [`__main__.py`](src/wasat/__main__.py) | Self-contained package execution entry point and CLI runner. Not part of the public library interface. |
| [`certs.py`](src/wasat/certs.py) | Client certificate generation and storage management (`ClientCertificateStore`, `FileClientCertificateStore`) for Gemini connections. |
| [`client.py`](src/wasat/client.py) | Async client implementation (`Client`), including TLS connection establishment, request dispatch, redirect handling, timeout enforcement, and stream wrapping via `WrappedStreamReader`. |
| [`response.py`](src/wasat/response.py) | Represents Gemini server response (`Response`), handling response body caching, text decoding with charsets, chunked streaming (`iter_chunks`), and async context management. |
| [`status.py`](src/wasat/status.py) | Gemini protocol status code parsing and category logic (`StatusCode`). |
| [`trust.py`](src/wasat/trust.py) | Trust-On-First-Use (TOFU) validation logic and default file-based storage backend (`FileTrustStore`). |
| [`uri.py`](src/wasat/uri.py) | Gemini URI representation, parsing, and relative path resolution (`GeminiURI`). Uses a safe, undocumented-internal-free scheme-swapping method with `urllib.parse`. |
| [`exceptions.py`](src/wasat/exceptions.py) | Custom exceptions for the library (`WasatError`, `URIError`, `ProtocolError`, `ConnectionError`, `SecurityError`, `RedirectError`). |

---

## Code Style

- **Python Version**: Target Python 3.12+ (since `requires-python = ">=3.12"`). Favour newer syntax such as `union types (X | Y)`, `TypeAlias`, and structural pattern matching where appropriate.
- **Type Hints**: Always write full type hints that pass `mypy` in strict mode. Use structural protocols (like `ReaderProtocol` in [`response.py`](src/wasat/response.py)) rather than casting to `Any` or `any` when working with dynamic types.
- **Docstrings**: Always write full Google-style docstrings for every module, class, method, and function. Do *not* include type annotations in the docstring text.
  - Docstrings always start on the same line as the opening triple quote.
  - The closing triple quote is on its own line for multi-line docstrings.
  - Document all file-wide types, module-level constants, and instance attributes/properties established via `__init__` with a clear one-line docstring immediately following the assignment/definition (e.g., `_CONST = "val"\n  """One-line explainer."""`).
  - Cross-references should use mkdocstrings-compatible Markdown formatting:
    - Inline code: single backticks (\`like_this\`).
    - Cross-references: `[`ClassName`][module.ClassName]` or `[module.ClassName][]`. Do not use Sphinx markup.
- **Descriptive Naming**: Use full, descriptive names for all classes, methods, functions, and variables. Avoid abbreviations.
- **Language**: Use British English for all documentation and naming of classes, methods, functions and variables.
- **Modularization**: Keep modules focused and relatively small. When introducing new components (e.g., custom parsers, protocol extensions), create a new module rather than expanding existing ones.

---

## Code Quality

Before pushing changes or submitting a PR, make sure all code quality checks pass:

| Command | What it checks |
|---|---|
| `make stricttypecheck` | Static type checks with `mypy --strict` |
| `make lint` | Lint check using `ruff check` |
| `make codestyle` | Formatting check using `ruff format --check` |
| `make spellcheck` | Spell check using `codespell` |
| `make test` | Runs the test suite |

Run the definitive check wrapper:
```bash
make checkall
```
To automatically fix style, formatting, and lint issues, run:
```bash
make tidy
```

---

## Repository Tools

- **UV Package Manager**: We use `uv` for environment, locking, and dependency management.
  - Do not edit the dependency list in [pyproject.toml](pyproject.toml) manually. Use `uv add <dependency>` and `uv remove <dependency>`.
  - Always keep `uv.lock` up to date. After adding dependencies, run `uv sync`.
  - Run `make setup` after initial clone to install requirements and pre-commit hooks.
  - The [Makefile](Makefile) is the canonical interface for all development tasks. Keep it tidy and documented.

---

## Testing

All tests live in the [tests/](tests/) directory:

- [tests/test_certs.py](tests/test_certs.py)
- [tests/test_client.py](tests/test_client.py)
- [tests/test_main.py](tests/test_main.py)
- [tests/test_response.py](tests/test_response.py)
- [tests/test_status.py](tests/test_status.py)
- [tests/test_uri.py](tests/test_uri.py)

- **Test Execution**: Run `make test` to execute the full test suite.
- **Coverage**: Any new functionality or resolved issues **must** have associated tests.
- Do not bypass, disable, or delete tests to mask failures; fix the underlying bugs.

---

## Documentation

Documentation is managed using MkDocs and mkdocstrings.
- Run `make docs` to build the system documentation locally.
- Run `make rtfm` to start the local interactive MkDocs preview server.
- Ensure that any changes to the public API are documented in docstrings and matched in user-facing documentation.

---

## Commits and PRs

- **Commit Messages**: Write commit messages in the imperative mood (e.g., "Add timeout configuration parameter", not "Added..." or "Adds...").
- **Focused Commits**: Maintain focused, atomic commits—one logical change per commit.

---
[//]: # (AGENTS.md ends here)
