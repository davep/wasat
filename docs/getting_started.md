# Getting Started

This guide introduces the primary components of Wasat and demonstrates how to perform requests, stream response bodies, and handle certificate verification.

All of the public classes, protocols, and exceptions are exposed at the top level of the package. You can import them directly from `wasat`.

## Core Components

The following classes and protocols form the core interface of the library:

- **[Client][wasat.client.Client]**: The asynchronous client used to configure and dispatch requests.
- **[Response][wasat.response.Response]**: Represents the server's response, supporting text decoding and chunked body streaming.
- **[GeminiURI][wasat.uri.GeminiURI]**: A utility class to parse, validate, and resolve Gemini URIs safely.
- **[StatusCode][wasat.status.StatusCode]**: An integer enumeration representing the official status codes of the Gemini Protocol, featuring helper properties to categorise statuses.
- **[TrustStore][wasat.trust.TrustStore]**: A protocol defining the trust verification interface.
- **[FileTrustStore][wasat.trust.FileTrustStore]**: The default file-based Trust-On-First-Use (TOFU) backend that stores trusted certificate fingerprints.

---

## Basic Request

To execute a request, initialise a [Client][wasat.client.Client] and use its request method. The client automatically manages connections, TLS negotiation, and redirects.

```python
import asyncio
from wasat import Client, WasatError

async def main():
    # Use "tofu" verification mode for standard self-signed Gemini certificates
    client = Client(verify_mode="tofu")

    try:
        # Perform the request (resolves host, port, TLS, and redirects)
        async with await client.request("gemini://geminiprotocol.net/") as response:
            print(f"Status: {response.status.value} ({response.status.name})")
            print(f"MIME type: {response.mime_type}")

            # Fetch and decode the response body text
            body = await response.text()
            print(body)

    except WasatError as e:
        print(f"Request failed: {e}")

if __name__ == "__main__":
    asyncio.run(main())
```

---

## Streaming Responses

For large responses or continuous streams, you can read the body incrementally to minimise memory usage. Use the [iter_chunks][wasat.response.Response.iter_chunks] method on the [Response][wasat.response.Response] object:

```python
import sys
from wasat import Client

async def download_file():
    client = Client(verify_mode="tofu")
    async with await client.request("gemini://example.com/large-file.bin") as response:
        if response.status.is_success:
            async for chunk in response.iter_chunks(chunk_size=1024):
                sys.stdout.buffer.write(chunk)
```

---

## Custom Trust Verification and TOFU

By default, Wasat employs a Trust-On-First-Use (TOFU) security model via [FileTrustStore][wasat.trust.FileTrustStore]. When a new certificate is encountered, you can customise the behaviour by providing an asynchronous `on_new_certificate` callback to the [Client][wasat.client.Client]:

```python
async def confirm_cert(host: str, port: int, fingerprint: str) -> bool:
    print(f"Encountered a new certificate for {host}:{port}")
    print(f"Fingerprint: sha256:{fingerprint}")
    response = input("Trust this certificate? [y/N]: ").strip().lower()
    return response == "y"

client = Client(
    verify_mode="tofu",
    on_new_certificate=confirm_cert
)
```

---

## Exception Hierarchy

All exceptions raised by the library inherit from the base class [WasatError][wasat.exceptions.WasatError]. When managing errors, you can catch specific sub-classes for finer control:

- **[URIError][wasat.exceptions.URIError]**: Raised when a given URI cannot be parsed or resolved.
- **[ProtocolError][wasat.exceptions.ProtocolError]**: Raised when server response headers violate the Gemini protocol specification.
- **[ConnectionError][wasat.exceptions.ConnectionError]**: Raised when network connections fail, drop, or time out.
- **[SecurityError][wasat.exceptions.SecurityError]**: Raised when TLS verification fails or a TOFU fingerprint does not match the trust store.
- **[RedirectError][wasat.exceptions.RedirectError]**: Raised when a redirect loop is detected or the maximum redirect limit is exceeded.
