# Wasat ChangeLog

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
