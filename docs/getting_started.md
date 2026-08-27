# Getting Started

This guide introduces the primary components of Wasat and demonstrates how to perform requests, stream response bodies, and handle certificate verification.

All of the public classes, protocols, and exceptions are exposed at the top level of the package. You can import them directly from `wasat`.

## Core Components

The following classes and protocols form the core interface of the library:

- **[Client][wasat.client.Client]**: The asynchronous client used to configure and dispatch requests.
- **[Response][wasat.response.Response]**: Represents the server's response, exposing the target URI (`uri`), the originally requested URI (`requested_uri`), redirect history (`history`), client certificate details (`client_cert`, `client_cert_path`, `client_key_path`, `client_cert_used`), server TLS certificate details (`server_cert`, `server_cert_der`, `server_cert_fingerprint`), certificate verification method (`verification_method`), text decoding, and chunked body streaming.
- **[ServerCertificate][wasat.certs.ServerCertificate]**: A high-level representation of a server's TLS certificate providing parsed attributes (e.g. subject, issuer, validity dates, SANs, fingerprint). Access it lazily via `response.server_cert`.
- **[ClientCertificate][wasat.certs.ClientCertificate]**: A representation of a client TLS certificate and private key pair, exposing subject attributes, validity dates, public key info, fingerprint, and associated Gemini scopes. Access it lazily via `response.client_cert`.
- **[GeminiURI][wasat.uri.GeminiURI]**: A utility class to parse, validate, and resolve Gemini URIs safely.
- **[StatusCode][wasat.status.StatusCode]**: An integer enumeration representing the official status codes of the Gemini Protocol, featuring helper properties to categorise statuses.
- **[TrustStore][wasat.trust.TrustStore]**: A protocol defining the trust verification interface.
- **[FileTrustStore][wasat.trust.FileTrustStore]**: The default file-based Trust-On-First-Use (TOFU) backend that stores trusted certificate fingerprints.
- **[ClientCertificateStore][wasat.certs.ClientCertificateStore]**: A protocol defining the client certificate storage and management interface.
- **[FileClientCertificateStore][wasat.certs.FileClientCertificateStore]**: The default file-based store managing client certificates, keys, and scope mappings.

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

    except WasatError as error:
        print(f"Request failed: {error}")

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

## Custom Trust Verification, TOFU, and Hybrid Mode

Wasat supports multiple certificate verification modes via `verify_mode`:

- `"hybrid"`: Combines system CA validation with TOFU fallback. Wasat first attempts to validate certificates using system CAs (e.g. Let's Encrypt). If CA verification fails because the certificate is untrusted or self-signed, it falls back to TOFU validation. If CA verification fails due to certificate expiration, hostname mismatch, or revocation, fallback is denied and a `SecurityError` is raised immediately.
- `"tofu"`: Strict Trust-On-First-Use validation using [FileTrustStore][wasat.trust.FileTrustStore].
- `"ca"`: Validates certificates strictly against system CAs.
- `"off"`: Disables certificate verification.

When a new self-signed certificate is encountered in `"tofu"` or `"hybrid"` mode, you can customise the behaviour by providing an asynchronous `on_new_certificate` callback to the [Client][wasat.client.Client]:

```python
async def confirm_cert(host: str, port: int, fingerprint: str) -> bool:
    print(f"Encountered a new certificate for {host}:{port}")
    print(f"Fingerprint: sha256:{fingerprint}")
    response = input("Trust this certificate? [y/N]: ").strip().lower()
    return response == "y"

client = Client(
    verify_mode="hybrid",
    on_new_certificate=confirm_cert
)
```

---

## Client Certificate Authentication

Gemini supports client certificates as a method of user authentication (e.g. for session tracking or user identities). When a server requires a client certificate, it returns a `60` status code (CLIENT_CERTIFICATE_REQUIRED).

Wasat provides a [FileClientCertificateStore][wasat.certs.FileClientCertificateStore] to manage, scope, and persist generated client certificates.

### Automatic Certificate Handling

You can configure the client to automatically prompt your application, generate self-signed certificates, and retry requests when faced with a client certificate requirement:

```python
from typing import Literal
from wasat import Client, GeminiURI, ClientCertificateStore

async def handle_cert_request(
    uri: GeminiURI,
    store: ClientCertificateStore
) -> Literal["transient", "persistent", "ignore"]:
    # Determine whether to generate a transient/persistent certificate, or ignore.
    # Transient certificates are stored in a temporary folder and cleaned up at exit.
    print(f"Server at {uri.host} requested a client certificate.")
    return "transient"

client = Client(
    verify_mode="tofu",
    on_client_certificate_required=handle_cert_request
)
```

### Shared Hosts and Certificate Mapping

On a shared host (like `station.martinrue.com`), where multiple independent users have their own directories (e.g. `/davep` and `/otheruser`), scoping the certificate to the host root `/` is a privacy risk because other users could request your client certificate. Instead, you should keep the certificate scoped to the specific path.

To reuse the certificate you generated on the sign-up page (e.g., `/join`) for your home page (e.g., `/davep`), you can retrieve the existing certificate from the store inside the callback and associate it with the new path using [register_credentials][wasat.certs.ClientCertificateStore.register_credentials]:

```python
async def handle_cert_request(uri: GeminiURI, store: ClientCertificateStore) -> str:
    # If visiting your page and the cert is not yet registered, map it from /join
    if uri.host == "station.martinrue.com" and uri.path.startswith("/davep"):
        join_uri = GeminiURI("gemini://station.martinrue.com/join")
        join_creds = await store.get_credentials(join_uri)
        if join_creds is not None:
            # Register the existing /join cert files for /davep
            await store.register_credentials(uri, join_creds[0], join_creds[1])
            return "persistent"

    # Default to generating a new transient cert
    return "transient"
```

### Redirection and Certificate Reuse

When a request is redirected (e.g. from `gemini://example.com/join` to `gemini://example.com/dashboard`), and a client certificate was successfully used to authenticate a prior request in the redirect chain, Wasat will automatically retrieve and reuse the same certificate for any subsequent redirect targets on the same host and port.

Additionally, to ensure user session continuity across subsequent visits, once the redirect chain succeeds (returning a success or redirect status code), Wasat will automatically register/re-bind the certificate to the landed URI's scope. This ensures that future direct requests to the target URI will automatically present the certificate without needing to go through the initial redirect flow again.

### Manual Certificate Handling

If you do not register the callback, you can manually generate, store, and present certificates inside your application flow:

```python
from wasat import Client, StatusCode

client = Client(verify_mode="tofu")

response = await client.request("gemini://example.com/protected")
if response.status == StatusCode.CLIENT_CERTIFICATE_REQUIRED:
    # Generate a certificate for the host/path scope and save it in the store.
    # Set valid_days=None to create a certificate that expires on 9999-12-31.
    await client.client_cert_store.create_credentials(
        response.uri,
        transient=True,
        common_name="my_identity",
        email="user@example.com",
        valid_days=None
    )

    # Retry the request; the client automatically detects and loads the new cert
    response = await client.request("gemini://example.com/protected")
```

### Certificate Management and Inspection

The certificate store provides comprehensive APIs for building management interfaces (such as client identity pickers and settings UIs):

```python
from wasat import FileClientCertificateStore, GeminiURI

store = FileClientCertificateStore("~/.config/my_app/certs")

# 1. Create a standalone persona / certificate
persona = await store.create_certificate(
    name="dave_persona",
    common_name="Dave Pearson",
    email="dave@example.com",
    scopes=[
        "gemini://example.com/forum",
        "station.martinrue.com:1965/davep",
    ]
)

# 2. List all certificates in the store
certs = await store.list_certificates()
for cert in certs:
    print(f"CN: {cert.subject_common_name}")
    print(f"Fingerprint: {cert.fingerprint}")
    print(f"Key: {cert.key_type} {cert.key_size}-bit")
    print(f"Expires: {cert.not_after}")
    print(f"Associated scopes: {cert.scopes}")

# 3. Look up a certificate by URI, scope, fingerprint, or path
cert = await store.get_certificate("example.com/forum")

# 4. Associate an existing certificate with additional scopes
if cert is not None:
    await store.associate_scope(cert, "gemini://another-capsule.org/blog")

# 5. Disassociate a scope without deleting the certificate files
await store.disassociate_scope("example.com/forum")

# 6. Delete a certificate and all associated scope mappings
if cert is not None:
    await store.delete_certificate(cert)
```

### Importing and Exporting Certificates

You can import external certificates (such as identity backups from other Gemini clients, OpenSSL keypairs, or pasted PEM text) and export identities for backup:

```python
from pathlib import Path
from wasat import ClientCertificate, FileClientCertificateStore

store = FileClientCertificateStore("~/.config/my_app/certs")

# 1. In-memory or file import (supports combined or separate cert + key)
cert_bundle = Path("identity.pem").read_text()
imported_cert = await store.import_certificate(
    source=cert_bundle,
    name="imported_identity",
    scopes=["gemini://example.com/blog"],
)

# 2. Construct an in-memory ClientCertificate instance directly from PEM
cert = ClientCertificate.from_pem(cert_bundle)

# 3. Export as a combined .pem backup bundle with strict permissions (0600)
await store.export_certificate(
    identifier=imported_cert,
    target_path="~/backups/identity_backup.pem",
    combined=True,
)

# 4. Export as separate .crt and .key files into a directory
await store.export_certificate(
    identifier="imported_identity",
    target_path="~/backups/keys/",
    combined=False,
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
