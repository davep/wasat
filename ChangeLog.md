# Wasat ChangeLog

## Unreleased

**Released: WiP**

- Added `ClientCertificate.from_pem` constructor to instantiate client
  certificates from in-memory PEM text or bytes, supporting combined
  bundles, separate certificate and private key inputs, or certificate-only
  data. ([#52](https://github.com/davep/wasat/pull/52))
- Updated `ClientCertificate.from_file` to automatically detect and extract
  private keys from single combined `.pem` files when `key_path` is omitted.
  ([#52](https://github.com/davep/wasat/pull/52))
- Added `ClientCertificate.to_combined_pem` method to serialise certificate
  and private key pairs into a single PEM byte sequence.
  ([#52](https://github.com/davep/wasat/pull/52))
- Added `ClientCertificate.export` method to export certificates and private
  keys to disk with restricted permissions (`0600`) on private keys.
  ([#52](https://github.com/davep/wasat/pull/52))
- Added `import_certificate` method to `ClientCertificateStore` protocol and
  `FileClientCertificateStore` implementation to import certificates from
  file paths, raw PEM bytes or strings, or `ClientCertificate` instances,
  with optional scope associations and safe file permissions.
  ([#52](https://github.com/davep/wasat/pull/52))
- Added `export_certificate` method to `ClientCertificateStore` protocol and
  `FileClientCertificateStore` implementation to look up certificates by
  fingerprint, common name, file stem, or scope and export them as combined
  bundles or separate files. ([#52](https://github.com/davep/wasat/pull/52))
- Enhanced `FileClientCertificateStore.get_certificate` to support lookup by
  certificate subject Common Name and file stem.
  ([#52](https://github.com/davep/wasat/pull/52))
- Fixed an issue where unscoped transient certificates were omitted from
  `list_certificates` in `FileClientCertificateStore` and could not be
  retrieved or managed via `get_certificate`, `associate_scope`, or
  `delete_certificate`. ([#51](https://github.com/davep/wasat/pull/51))

## v1.4.0

**Released: 2026-08-23**

- Added `ClientCertificate` class representing client TLS certificates and
  private keys with full access to parsed subject attributes (Common Name,
  email, user ID, organisation, country), issuer, validity timestamps,
  expiration and self-signed checks, public key information, SHA-256
  fingerprint, and associated scopes. Exported `ClientCertificate` as a
  public type at the top level.
  ([#48](https://github.com/davep/wasat/pull/48))
- Added `normalize_scope` helper function to normalise Gemini URIs and scope
  strings into canonical `host:port/path` format, and exported it at the top
  level. ([#48](https://github.com/davep/wasat/pull/48))
- Added `list_certificates` method to the `ClientCertificateStore` protocol
  and `FileClientCertificateStore` implementation to enumerate all stored
  and transient client certificates along with their associated scopes.
  ([#48](https://github.com/davep/wasat/pull/48))
- Added `get_certificate` method to `ClientCertificateStore` protocol and
  `FileClientCertificateStore` implementation to retrieve client
  certificates by URI, scope, SHA-256 fingerprint, or file path/name.
  ([#48](https://github.com/davep/wasat/pull/48))
- Added `create_certificate` method to `ClientCertificateStore` protocol and
  `FileClientCertificateStore` implementation to allow generating standalone
  identities or associating certificates with multiple scopes.
  ([#48](https://github.com/davep/wasat/pull/48))
- Added `associate_scope` and `disassociate_scope` methods to
  `ClientCertificateStore` protocol and `FileClientCertificateStore`
  implementation to allow dynamically managing scope bindings for existing
  certificates without duplicating certificate files on disk.
  ([#48](https://github.com/davep/wasat/pull/48))
- Added `delete_certificate` and `delete_exact_scope` methods to
  `ClientCertificateStore` protocol and `FileClientCertificateStore`
  implementation for deleting certificates and unbinding specific scopes
  safely. ([#48](https://github.com/davep/wasat/pull/48))

## v1.3.1

**Released: 2026-07-30**

- Added `ServerCertificate` class and `Response.server_cert` property to
  provide high-level access to parsed server TLS certificate attributes
  (subject/issuer CNs, validity dates, SANs, serial number, fingerprint, and
  status checks). Exported `ServerCertificate` as a public type at the top
  level. ([#45](https://github.com/davep/wasat/pull/45))
- Updated the CLI (`wasat`) to add a `--show-cert` flag for displaying
  detailed server TLS certificate information.
  ([#45](https://github.com/davep/wasat/pull/45))

## v1.3.0

**Released: 2026-07-30**

- Refined `hybrid` certificate verification mode to only fall back to TOFU
  when CA validation fails due to an untrusted root or self-signed
  certificate. Certificate failures caused by expiration, hostname mismatch,
  or revocation now immediately raise `SecurityError`.
  ([#41](https://github.com/davep/wasat/pull/41))
- Added `VerifyMode` as a type and exported it at the top level.
  ([#41](https://github.com/davep/wasat/pull/41))
- Added `server_cert_der`, `server_cert_fingerprint`, and
  `verification_method` properties to `Response` to expose server TLS
  certificate details and the verification method used.
  ([#43](https://github.com/davep/wasat/pull/43))
- Added `VerificationMethod` type alias and exported it at the top level.
  ([#43](https://github.com/davep/wasat/pull/43))
- Updated the CLI (`wasat`) to display `Verification Method` and
  `Certificate Fingerprint` when running in verbose (`-v` / `--verbose`) mode.
  ([#43](https://github.com/davep/wasat/pull/43))

## v1.2.0

**Released: 2026-07-30**

- Added `--verify-mode` to the CLI of the library so the certificate
  verification mode can be tested.
  ([#39](https://github.com/davep/wasat/pull/39))
- Added `hybrid` certificate verification mode to `Client` to combine system
  CA validation with TOFU fallback.
  ([#39](https://github.com/davep/wasat/pull/39))

## v1.0.1

**Released: 2026-07-21**

- Fixed unhandled `ssl.SSLEOFError`, `ssl.SSLError`, and `OSError`
  exceptions during request dispatch and response header reading by mapping
  them to `ConnectionError`. ([#36](https://github.com/davep/wasat/pull/36))

## v1.0.0

**Released: 2026-07-21**

- Promoted to "stable". ([#34](https://github.com/davep/wasat/pull/34))

## v0.8.0

**Released: 2026-07-18**

- Added `GeminiURI.without_query`.
  ([#32](https://github.com/davep/wasat/pull/32))
- Added `GeminiURI.parent` ([#32](https://github.com/davep/wasat/pull/32))
- Added `GeminiURI.root` ([#32](https://github.com/davep/wasat/pull/32))

## v0.7.0

**Released: 2026-07-16**

- Added `GeminiURI.MAXIMUM_LENGTH`.
  ([#29](https://github.com/davep/wasat/pull/29))
- Added `len` support to `GeminiURI` (reports the byte length of the URI).
  ([#29](https://github.com/davep/wasat/pull/29))
- Added `GeminiURI.bytes_left`.
  ([#29](https://github.com/davep/wasat/pull/29))
- Added `GeminiURI.too_long`.
  ([#29](https://github.com/davep/wasat/pull/29))

## v0.6.1

**Released: 2026-07-14**

- Fixed `GeminiURI.with_default_scheme` treating `example.com` in
  `example.com:1966` as a scheme.
  ([#27](https://github.com/davep/wasat/pull/27))

## v0.6.0

**Released: 2026-07-14**

- Relaxed the type of the parameters for `GeminiURI.__init__`.
  ([#24](https://github.com/davep/wasat/pull/24))
- Added `GeminiURI.with_default_scheme`
  ([#25](https://github.com/davep/wasat/pull/25))

## v0.5.0

**Released: 2026-07-13**

- Added `get_hosts` asynchronous method to the `TrustStore` protocol and
  `FileTrustStore` implementation to retrieve all stored host and port
  combinations from the trust store.
  ([#22](https://github.com/davep/wasat/pull/22))
- Added `trust_store` public property to the `Client` class to expose the
  underlying trust store. ([#22](https://github.com/davep/wasat/pull/22))

## v0.4.0

**Released: 2026-07-12**

- Added a new `replace` method to `GeminiURI` to allow creating a copy of a
  URI with specified components replaced, including removing optional
  components like path or query by setting them to `None`.
  ([#19](https://github.com/davep/wasat/pull/19))
- Added component-specific builder methods `with_host`, `with_port`, and
  `with_path` to `GeminiURI`.
  ([#19](https://github.com/davep/wasat/pull/19))
- Updated `with_query` on `GeminiURI` to allow setting, replacing, or
  clearing (by passing `None`) the query parameter.
  ([#19](https://github.com/davep/wasat/pull/19))
- Updated `GeminiURI` constructor's internal error handling to catch
  `ValueError` and other parsing anomalies (e.g. from negative/out-of-range
  ports) raised by `urlparse`, converting them into `URIError`.
  ([#19](https://github.com/davep/wasat/pull/19))

## v0.3.2

**Released: 2026-07-11**

- Updated redirect certificate handling to automatically register/re-bind an
  inherited client certificate to the final landing URI's scope upon
  successful completion (status code 2x or 3x) of a redirect chain. This
  allows future direct requests to the target URI to automatically reuse the
  certificate without going through the initial redirect flow again.
  ([#17](https://github.com/davep/wasat/pull/17))

## v0.3.1

**Released: 2026-07-11**

- Fixed client certificate handling during redirects on the same host and
  port. If a client certificate was successfully used for a request in a
  redirect chain, the client automatically retrieves and reuses it for any
  subsequent redirected requests targeting the same host and port,
  preventing certificate information loss on sibling paths.
  ([#14](https://github.com/davep/wasat/pull/14))
- Added `register_credentials` to the `ClientCertificateStore` protocol and
  `FileClientCertificateStore` implementation to allow programmatically
  registering/associating existing client certificate files with a new URI
  scope. ([#14](https://github.com/davep/wasat/pull/14))
- Updated the client connection logic to skip generating a new certificate
  if the `on_client_certificate_required` callback has already registered
  exact credentials for the URI, allowing manual registration in the
  callback. ([#14](https://github.com/davep/wasat/pull/14))

## v0.3.0

**Released: 2026-07-11**

- Added `client_cert_path` and `client_cert_used` properties to `Response`
  to expose the path to the client certificate and a boolean flag indicating
  if one was used for the connection.
  ([#11](https://github.com/davep/wasat/pull/11))

## v0.2.1

**Released: 2026-07-10**

- Fixed client certificate path prefix matching in `get_candidate_scopes` to
  support both trailing and non-trailing slash parent directory paths,
  ensuring certificates registered for paths like `/foo/bar` (no trailing
  slash) are correctly matched and offered for subpaths (e.g.
  `/foo/bar/baz`). ([#9](https://github.com/davep/wasat/pull/9))
- Added `has_exact_credentials` to the `ClientCertificateStore` protocol and
  `FileClientCertificateStore` implementation.
  ([#9](https://github.com/davep/wasat/pull/9))
- Updated the client connection logic to use `has_exact_credentials` when
  checking whether a client certificate requirement is new/fresh, ensuring
  the client correctly prompts the user for a new certificate if a parent
  certificate is rejected by the server, while avoiding infinite loops.
  ([#9](https://github.com/davep/wasat/pull/9))

## v0.2.0

**Released: 2026-07-10**

- Allowed passing `None` to `valid_days` in `generate_self_signed_cert` and
  `create_credentials` to generate client certificates that expire on
  `9999-12-31`. ([#7](https://github.com/davep/wasat/pull/7))

## v0.1.0

**Released: 2026-06-24**

- Added support for generating and storing client certificates.
  ([#3](https://github.com/davep/wasat/pull/3))
- Added support for handling Gemini Protocol input requests (status codes 10
  and 11) in the CLI. ([#4](https://github.com/davep/wasat/pull/4))
- Added `uri` property to `Response` to expose the target URI of the
  request. ([#5](https://github.com/davep/wasat/pull/5))
- Added `history` property to `Response` to expose any redirection history.
  ([#5](https://github.com/davep/wasat/pull/5))
- Added `requested_uri` property to `Response` to expose the
  originally-requested URI in any response.
  ([#5](https://github.com/davep/wasat/pull/5))
- Updated the CLI to show the originally-requested URI and the redirection
  history, in verbose mode, if there was a redirection.
  ([#5](https://github.com/davep/wasat/pull/5))

## v0.0.1

**Released: 2026-06-17**

- Initial version of the library.

[//]: # (ChangeLog.md ends here)
