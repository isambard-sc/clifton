<!--
SPDX-FileCopyrightText: © 2024 Matt Williams <matt.williams@bristol.ac.uk>
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# Making a release

Releases are completely automated by GitHub Actions:
1. Make sure the [changelog](./CHANGELOG.md) is up to date.
   A release cannot be made if there is nothing in the changelog in the `Unreleased` section.
2. Go the the [Release](https://github.com/isambard-sc/clifton/actions/workflows/release.yml) workflow page.
3. Click "Run workflow" in the top right.
4. Make sure the `master` branch is selected.
5. In the box below, type `patch`, `minor` or `major`, depending on the [SemVer level](https://semver.org) of release to make.
6. Press the "Run workflow" button.

This will kick off a series of chained workflows, culminating in a new release appearing on the [Releases page](https://github.com/isambard-sc/clifton/releases).
