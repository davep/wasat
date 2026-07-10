# Wasat ChangeLog

## Unreleased

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
