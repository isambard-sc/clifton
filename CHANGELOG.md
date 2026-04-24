# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Fixed

- `clifton auth --write-config=true` now adds the `Include` line to the main SSH config file correctly (PR #168). Thanks to @D-Simona-G.

## [0.3.0] - 2025-10-17

### Added

- Clifton now supports certificate response version 3.
- Add option to automatically write the SSH config on a successful auth using `clifton auth --write-config=true` (PR #139). Thanks to David Llewellyn-Jones (@llewelld).

### Fixed

- Quote paths in config files. This is required for paths which have spaces in them.
- Allow `--config-file` to be passed at any level of subcommands.
- Allow `clifton clear-cache` to work if cache directory is missing.
- Only notify to write config if a change is detected.
- Store the absolute path of passed identity files, rather than their relative position from where `auth` was run (Issue #98).

### Changed

- Retrieve OIDC client ID from the CA rather than setting it in the config. Requires version 0.3 of Conch.
- Make the `clifton ssh-command` command hidden.

## [0.2.0] - 2024-09-13

### Changed

- Use the new [Conch](https://github.com/isambard-sc/conch/) CA
- Only write the SSH config if the contents has actually changed.
- Shorten the timeout for version check to 5 seconds.

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

[0.3.0]: https://github.com/isambard-sc/clifton/releases/tag/0.3.0
[0.2.0]: https://github.com/isambard-sc/clifton/releases/tag/0.2.0
[0.1.4]: https://github.com/isambard-sc/clifton/releases/tag/0.1.4
[0.1.3]: https://github.com/isambard-sc/clifton/releases/tag/0.1.3
[0.1.2]: https://github.com/isambard-sc/clifton/releases/tag/0.1.2
[0.1.1]: https://github.com/isambard-sc/clifton/releases/tag/0.1.1
[0.1.0]: https://github.com/isambard-sc/clifton/releases/tag/0.1.0
