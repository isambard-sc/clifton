# SPDX-FileCopyrightText: © 2024 Matt Williams <matt.williams@bristol.ac.uk>
# SPDX-License-Identifier: MIT

# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

import tomllib
from pathlib import Path

project = 'Clifton'
copyright = '©&nbsp;2025, <a href="https://www.bristol.ac.uk/research/centres/bristol-supercomputing/">Bristol Centre for Supercomputing</a>, <a href="https://creativecommons.org/licenses/by-sa/4.0/">CC‑BY‑SA&nbsp;4.0</a>'
author = 'Matt Williams'
release = tomllib.loads((Path(__file__).resolve().parent.parent / "Cargo.toml").read_text())["package"]["version"]

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = [
    "sphinx_design",
    "sphinx_copybutton",
]

templates_path = ['_templates']
exclude_patterns = []

html_show_sphinx = False

copybutton_exclude = '.linenos, .gp'

# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

html_theme = "shibuya"
html_static_path = ['_static']
html_favicon = "_static/favicon.svg"
# html_logo = "_static/favicon.svg"
html_theme_options = {
  "accent_color": "blue",
}

## -- Epilog --

rst_epilog = f"""
.. |version| replace:: {release}
"""
