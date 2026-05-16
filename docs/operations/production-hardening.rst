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

Add an Authentication Layer
-----------------------------

TracePcap has **no built-in user authentication**. For multi-user or
internet-facing deployments, place an authentication layer in front of nginx:

- **OAuth2 / OIDC proxy** — e.g. `oauth2-proxy <https://oauth2-proxy.github.io/oauth2-proxy/>`_
  in front of nginx.
- **Basic auth** — configure nginx ``auth_basic`` with an ``.htpasswd`` file.
- **VPN / firewall** — restrict access to trusted IP ranges at the network
  level.

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

Set ``MAX_UPLOAD_SIZE_BYTES`` in ``.env`` appropriate for your storage
capacity and user needs:

.. code-block:: ini

   MAX_UPLOAD_SIZE_BYTES=1073741824  # 1 GB

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
