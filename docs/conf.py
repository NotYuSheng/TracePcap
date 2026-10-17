# Configuration file for the Sphinx documentation builder.
# https://www.sphinx-doc.org/en/master/usage/configuration.html

project = "TracePcap"
copyright = "2025–2026, TracePcap Contributors"
author = "TracePcap Contributors"
release = "0.1.1"
version = "0.1.1"
today = "2026-06-26"

extensions = ["sphinx_rtd_theme", "sphinx_sitemap"]

templates_path = ["_templates"]
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]

# Canonical site root — required for correct <link rel="canonical"> tags and for
# the sitemap. Trailing slash is required by sphinx-sitemap.
html_baseurl = "https://notyusheng.github.io/TracePcap/"

# sphinx-sitemap: emit sitemap.xml at the site root so search engines can crawl
# the full page list. Single (no versioned/translated builds) -> no {version}/{lang}.
sitemap_url_scheme = "{link}"

# Default meta description + keywords shown in search-engine snippets, prepended to
# every page via rst_prolog (there is no `html_meta` config key in Sphinx core).
# A page can override the description with its own `.. meta::` directive at the top.
rst_prolog = """
.. meta::
   :description: TracePcap is a self-hosted, offline-capable PCAP analysis tool for black-box network traffic forensics — reconstructing device inventory, topology, sessions, and threats from captured packets alone.
   :keywords: PCAP analysis, network forensics, packet capture, deep packet inspection, nDPI, Wireshark, self-hosted, offline, incident response, network audit
"""

html_theme = "sphinx_rtd_theme"
html_static_path = []  # populate when screenshots are added under _static/
html_logo = None
html_theme_options = {
    "navigation_depth": 4,
    "titles_only": False,
}
