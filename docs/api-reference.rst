API Reference
=============

TracePcap exposes a RESTful API documented with **SpringDoc OpenAPI**
(Swagger UI).

Accessing Swagger UI
--------------------

When the application is running, navigate to:

``http://localhost:80/swagger-ui.html``

(Replace ``80`` with your configured ``NGINX_PORT``.)

The Swagger UI provides:

- A list of all available endpoints grouped by controller.
- Request and response schemas.
- An interactive "Try it out" panel to execute API calls directly from the
  browser.

OpenAPI Specification
---------------------

The raw OpenAPI JSON specification is available at:

``http://localhost:80/v3/api-docs``

You can import this into tools like Postman, Insomnia, or any OpenAPI-compatible
client.

Static API Documentation
------------------------

A static snapshot of the API documentation is committed to the repository at
``docs/api/README.md`` for offline reference.

Key Endpoint Groups
-------------------

- **PCAP files** — upload, list, delete, download, and trigger re-analysis.
- **Conversations** — query, filter, sort, and export conversations.
- **Extracted files** — list and download extracted file objects.
- **Signatures** — read and update the custom signature rule set.
- **Story** — generate and retrieve AI narrative summaries.
- **Filters** — generate Wireshark/tcpdump filters from natural language.
- **Health** — liveness and readiness probes.
