# Wasat ChangeLog

## Unreleased

**Released: WiP**

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
