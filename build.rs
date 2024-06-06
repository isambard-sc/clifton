// SPDX-FileCopyrightText: © 2024 Matt Williams <matt.williams@bristol.ac.uk>
// SPDX-License-Identifier: MIT

fn main() {
    built::write_built_file().expect("Failed to acquire build-time information");
}
