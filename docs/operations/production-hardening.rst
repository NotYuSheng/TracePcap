Production Hardening
=====================

The default TracePcap configuration is optimised for quick local testing.
Before exposing the application to a wider audience, follow these steps.

Change Default Credentials
---------------------------

**MinIO:**

In ``docker-compose.yml``, change:

.. code-block:: yaml

   MINIO_ROOT_USER: minioadmin
   MINIO_ROOT_PASSWORD: minioadmin

to strong, unique credentials. Update any references in the backend service
environment as well.

**PostgreSQL:**

Change ``POSTGRES_PASSWORD`` to a strong password and update the backend's
``SPRING_DATASOURCE_PASSWORD`` to match.

Enable Authentication
---------------------

The base stack runs with **no login**. For multi-user or internet-facing
deployments, enable the bundled OIDC/Keycloak authentication via the production
overlay:

.. code-block:: bash

   PUBLIC_URL=https://app.example.com \
     docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build

This gates the API behind a Keycloak JWT and adds a login flow to the frontend.
**Change the demo credentials** (app login ``analyst`` / ``analyst`` and the
Keycloak admin ``user`` / ``P@ssw0rd``) before exposing the app. See
:doc:`../configuration/authentication` for the full walkthrough.

If you prefer an external identity layer instead, you can still front nginx
with an `oauth2-proxy <https://oauth2-proxy.github.io/oauth2-proxy/>`_,
nginx ``auth_basic``, or restrict access at the VPN/firewall level.

Configure SSL/TLS
-----------------

By default nginx serves HTTP. For production, terminate TLS at the nginx layer:

1. Obtain a certificate (e.g. from your internal CA or Let's Encrypt on an
   internet-connected machine).
2. Mount the certificate and key into the nginx container.
3. Update ``nginx/nginx.conf`` to add an HTTPS server block and redirect HTTP
   to HTTPS.

Adjust Upload Limits
---------------------

Upload limits are derived from a single memory budget. Set ``APP_MEMORY_MB`` in
``.env`` appropriate for your host RAM; the max upload size is 25% of it
(e.g. ``4096`` → 1 GB upload):

.. code-block:: ini

   APP_MEMORY_MB=4096  # ~1 GB max upload

Configure LLM Privacy
---------------------

If you use AI features, ensure ``LLM_API_BASE_URL`` points to a locally-hosted
model. Do **not** configure a cloud API endpoint if your PCAP data is sensitive.

Restrict MinIO Console Access
-------------------------------

The MinIO console is exposed on port ``9001`` by default. Remove or restrict
this port in ``docker-compose.yml`` for production:

.. code-block:: yaml

   # Comment out or remove:
   # ports:
   #   - "9001:9001"
