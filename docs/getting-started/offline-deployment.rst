Offline / Air-Gapped Deployment
================================

TracePcap is designed to support fully offline operation. This page covers
the workflow for deploying to a machine that has no internet access.

.. note::

   **Geolocation behaviour:** By default TracePcap geolocates external IPs
   from the bundled **DB-IP Lite MMDB** only, and never contacts
   `ipinfo.io <https://ipinfo.io>`_, so no configuration change is needed
   offline. All other features (packet parsing, nDPI, session reconstruction,
   file extraction, custom signatures) are fully offline at all times.

   If the MMDB file is not at the default location, set the ``GEO_MMDB_PATH``
   environment variable (or ``tracepcap.geo.mmdb-path`` in
   ``application.yml``).

No Runtime Egress (``GEO_FORCE_OFFLINE``)
-----------------------------------------

The only outbound call TracePcap can make at runtime is the optional
ipinfo.io geolocation lookup, and it's **off by default** in every stack:

.. code-block:: ini

   GEO_FORCE_OFFLINE=true   # the default

With it on (the default), TracePcap:

- **never** performs the connectivity probe or any ipinfo.io lookup — no
  outbound ``ipinfo.io`` connection is attempted (verifiable via egress
  logs / a firewall deny rule), and
- resolves geo **exclusively** from the bundled DB-IP Lite MMDB
  (``geo_source = mmdb`` on every result).

So TracePcap makes **no external network calls at runtime** (aside from a
locally-hosted LLM server, if configured — see below).

Setting ``GEO_FORCE_OFFLINE=false`` opts in to ipinfo.io, which adds ASN and
organisation: the backend then probes ``ipinfo.io`` (about every 60s while
resolving new external IPs), uses it when reachable, and falls back to the
MMDB otherwise. Even when it falls back, the outbound *attempt* still
happens, so leave it ``true`` on air-gapped or egress-monitored machines.

Overview
--------

.. note::

   Images saved by ``pull-and-save-images.sh`` match the architecture of the
   machine that ran it. For an air-gapped arm64 host, run it on an
   internet-connected arm64 machine. See :doc:`supported-architectures`.

1. On an **internet-connected** machine: pull all images and save them as
   ``.tar`` files.
2. **Transfer** the tarballs (plus a few scripts) to the offline machine.
3. On the **offline machine**: load the images and start the stack.

Step 1 — Pull and Save Images (online machine)
----------------------------------------------

.. code-block:: bash

   bash scripts/pull-and-save-images.sh

This creates an ``images/`` directory containing ``.tar`` files for every
service (backend, frontend, postgres, minio, nginx, …).

Step 2 — Transfer Files to the Offline Machine
-----------------------------------------------

Copy the following to the offline machine (USB drive, SCP, etc.):

.. code-block:: text

   images/                        # all .tar image archives
   docker-compose.offline.yml
   scripts/load-images.sh
   .env                           # copy from .env.example and configure first

Step 3 — Load Images and Start the Stack (offline machine)
----------------------------------------------------------

.. code-block:: bash

   # Load all images into Docker
   bash scripts/load-images.sh

   # Start the stack using the offline compose file
   docker compose -f docker-compose.offline.yml up -d

Authenticated Offline Deployment (Keycloak)
-------------------------------------------

The base offline stack runs with **no login**. To deploy offline *with* OIDC
authentication, use the ``docker-compose.offline-prod.yml`` overlay — the
offline equivalent of :doc:`../configuration/authentication` (which builds from
source and so cannot run air-gapped).

**Step 1 (online machine)** — include Keycloak when saving images:

.. code-block:: bash

   INCLUDE_KEYCLOAK=true bash scripts/pull-and-save-images.sh

This additionally saves the Keycloak image and an **auth-enabled frontend**
(``tracepcap-nginx-auth``) alongside the normal tarballs.

**Step 2** — also transfer ``docker-compose.offline-prod.yml`` and
``keycloak/realm-export.json`` (in addition to the files listed above).

**Step 3 (offline machine)** — load images, then start with the auth overlay,
setting ``PUBLIC_URL`` to the exact origin you browse to (scheme + host + port):

.. code-block:: bash

   bash scripts/load-images.sh

   PUBLIC_URL=http://<host>:8888 \
     docker compose -f docker-compose.offline.yml -f docker-compose.offline-prod.yml up -d

.. warning::
   ``PUBLIC_URL`` does **not** track ``NGINX_PORT`` (default
   ``http://localhost:8888``). It pins Keycloak's token issuer and the backend's
   issuer check, so the browser must load the app via this same origin. Do **not**
   include a trailing slash (use ``http://<host>:8888``, not
   ``http://<host>:8888/``) — it produces a double slash in the issuer URI and
   breaks JWT validation.

Create and manage logins at ``<PUBLIC_URL>/admin`` — see
:doc:`../configuration/user-management`. The realm seeds a demo app login of
``analyst`` / ``analyst``; **change it for any real deployment.** The Keycloak
admin account has no default — ``KEYCLOAK_ADMIN`` and
``KEYCLOAK_ADMIN_PASSWORD`` must be set in ``.env`` or the overlay aborts.

LLM Configuration for Offline Use
----------------------------------

AI features (Story Mode and its chat) require an OpenAI-compatible
inference server. The offline compose file defaults to:

.. code-block:: ini

   LLM_API_BASE_URL=http://localhost:1234/v1

Configure a locally-hosted LLM (e.g. `LM Studio <https://lmstudio.ai>`_ or
`Ollama <https://ollama.com>`_) and set ``LLM_API_BASE_URL`` in your ``.env``
before starting. See :doc:`../configuration/llm-setup` for details.

.. note::

   If no LLM server is available, TracePcap works fully without AI features —
   only Story Mode and its chat will be non-functional.
