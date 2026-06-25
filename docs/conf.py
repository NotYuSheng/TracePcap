# Configuration file for the Sphinx documentation builder.
# https://www.sphinx-doc.org/en/master/usage/configuration.html

project = "TracePcap"
copyright = "2025–2026, TracePcap Contributors"
author = "TracePcap Contributors"
release = "0.1.1"
version = "0.1.1"
today = "2026-06-26"

extensions = ["sphinx_rtd_theme"]

templates_path = ["_templates"]
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]

html_theme = "sphinx_rtd_theme"
html_static_path = []  # populate when screenshots are added under _static/
html_logo = None
html_theme_options = {
    "navigation_depth": 4,
    "titles_only": False,
}
