# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

## [0.1.4] - 2024-09-10
### Added
- Notify when a new version of Clifton has been released.
- Add hidden command `clifton clear-cache` to delete the cache folder.

## [0.1.3] - 2024-09-02
### Added
- Allow disabling the QR code display

## [0.1.2] - 2024-08-16
### Fixed
- Provide a better error message when passing an old format RSA key.

## [0.1.1] - 2024-08-07
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

[0.1.4]: https://github.com/isambard-sc/clifton/releases/tag/0.1.4
[0.1.3]: https://github.com/isambard-sc/clifton/releases/tag/0.1.3
[0.1.2]: https://github.com/isambard-sc/clifton/releases/tag/0.1.2
[0.1.1]: https://github.com/isambard-sc/clifton/releases/tag/0.1.1
[0.1.0]: https://github.com/isambard-sc/clifton/releases/tag/0.1.0
