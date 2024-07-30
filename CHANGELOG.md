# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased
### Added
- Print how long the certificate is valid for when downloaded.
- Fall back to a wider range of default identities.
- Add ability to disable opening the browser for authentication. Pass `--browser=false` to the `clifton auth` or set `open_browser = false` in the config file.
- Warn if using an unencrypted private key.

### Fixed
- Allow tilde in arguments.
- Don't fail if browser cannot be opened.

## [0.1.0] - 2024-07-12
### Added
- Initial release

[0.1.0]: https://github.com/isambard-sc/clifton/releases/tag/0.1.0
