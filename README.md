# Wasat: Async Gemini Protocol Client Library

Wasat is a fully type-hinted asynchronous client library for the [Gemini
Protocol](gemini://geminiprotocol.net), built with zero external
dependencies.

## Features

- **Async All the Way**: Built on top of Python's standard `asyncio` loop
  with streaming/chunking support.
- **Type Safe**: Fully typed API.
- **TOFU (Trust-On-First-Use) Support**: Secure by default with a built-in
  file-based TOFU store and custom interactive trust confirmation hooks.
- **Auto Redirect Handling**: Automatically handles temporary and permanent
  redirects (with protection against loops and infinite redirect limits),
  caching permanent redirects locally.
- **Client Authentication**: Native support for client TLS certificates.
- **Zero-Dependency**: Runs purely on Python's standard library.
- **CLI Utility**: Includes a `wasat` command-line interface out of the box.

---

## Installation

`wasat` is [available from pypi](https://pypi.org/project/wasat/) and can be
installed with your package installer of choice.

With `pip`:

```shell
pip install wasat
```

With `uv`:

```shell
uv add wasat
```

---

## Quick Start

### 1. Make a Simple Request

Use `Client` with standard async context managers to query a Gemini capsule
and decode the response:

```python
import asyncio
from wasat import Client, WasatError

async def main():
    # 'tofu' mode is ideal for standard Gemini capsules (self-signed certs)
    client = Client(verify_mode="tofu")

    try:
        # Perform the request (automatically resolves host, port, TLS, and redirects)
        async with await client.request("gemini://geminiprotocol.net/") as response:
            print(f"Status: {response.status.value} ({response.status.name})")
            print(f"MIME type: {response.mime_type}")

            # Fetch the decoded body text
            body = await response.text()
            print(body)

    except WasatError as e:
        print(f"Request failed: {e}")

if __name__ == "__main__":
    asyncio.run(main())
```

### 2. Streaming Chunk Responses

For large files or media streams, read the response body in chunks to
prevent exhausting memory:

```python
async with await client.request("gemini://example.com/large-file.txt") as response:
    if response.status.is_success:
        async for chunk in response.iter_chunks(chunk_size=1024):
            # Process each chunk as it arrives
            sys.stdout.buffer.write(chunk)
```

### 3. Client Certificate Authentication

If a server requires client auth (status code `60`), supply your certificate
files to the client configuration:

```python
client = Client(
    verify_mode="tofu",
    client_cert="/path/to/client.crt",
    client_key="/path/to/client.key"  # Optional if key is embedded in cert
)
```

### 4. Interactive TOFU Confirmation

Implement a custom asynchronous callback to prompt the user before trusting
new self-signed certificates:

```python
import sys

async def confirm_cert(host: str, port: int, fingerprint: str) -> bool:
    print(f"New certificate encountered for {host}:{port}")
    print(f"Fingerprint: sha256:{fingerprint}")
    response = input("Do you trust this certificate? [y/N]: ").strip().lower()
    return response == "y"

client = Client(
    verify_mode="tofu",
    on_new_certificate=confirm_cert
)
```

---

## Command Line Interface (CLI)

Wasat comes with a command-line interface to fetch Gemini capsules from your
shell:

```bash
# Basic fetch using the entrypoint script (uses TOFU)
uv run wasat gemini://geminiprotocol.net/

# Alternatively, execute the package directly using python -m
uv run python -m wasat gemini://geminiprotocol.net/

# Fetch a local or custom port capsule
uv run wasat gemini://localhost:1965/index.gmi
```

## License

MIT

[//]: # (README.md ends here)
