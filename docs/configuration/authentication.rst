Authentication (OIDC / Keycloak)
================================

TracePcap ships with **optional** OIDC authentication backed by a bundled
Keycloak identity provider. It is **off by default** — the base stack
(``docker compose up -d``) runs with no login, unchanged from before. Enable it
by layering the production overlay, which adds Keycloak, gates the backend API
behind a JWT, and rebuilds the frontend with the login flow.

.. note::
   Authentication is disabled in the base stack so single-user, air-gapped, and
   automated (e.g. Lanturn) deployments keep working with no login. Only the
   ``docker-compose.prod.yml`` overlay turns it on.

Enabling authentication
-----------------------

Run the base compose file **plus** the production overlay, setting
``PUBLIC_URL`` to the exact origin you browse to:

.. code-block:: bash

   PUBLIC_URL=http://localhost:8888 \
     docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build

``PUBLIC_URL`` must be the scheme + host + port you actually load the app from,
e.g. ``http://localhost:8888``, ``http://192.168.1.10:8888``, or a Tailscale
``http://100.x.y.z:8888``. It pins Keycloak's token issuer **and** the
backend's issuer check, so the browser must reach the app via this same origin.

.. warning::
   ``PUBLIC_URL`` does **not** track ``NGINX_PORT``. It defaults to
   ``http://localhost:8888``; for a default local prod run on port 80 you
   **must** set ``PUBLIC_URL=http://localhost`` (or your real port), or Keycloak
   will reject the ``redirect_uri`` / fail the issuer check.

Default demo login
------------------

The bundled ``tracepcap`` realm (``keycloak/realm-export.json``) ships with a
demo user. **Change these for any real deployment.**

.. list-table::
   :header-rows: 1
   :widths: 30 35 35

   * - Credential
     - Default
     - Where to change
   * - App login (demo user)
     - ``analyst`` / ``analyst``
     - Keycloak admin console → Users, or edit the realm export
   * - Keycloak admin
     - ``user`` / ``P@ssw0rd``
     - ``KEYCLOAK_ADMIN`` / ``KEYCLOAK_ADMIN_PASSWORD`` env vars

The Keycloak admin console is served same-origin at ``/admin``.

How it works
------------

**Same-origin proxy.** nginx proxies Keycloak (the ``/realms``, ``/resources``,
``/admin``, ``/js`` paths) so the browser reaches the identity provider at the
**same host:port** it loaded the app from. There is no second exposed port and
no CORS. The frontend derives the OIDC authority from ``window.location`` at
runtime, so nothing about the host is baked into the build.

**Frontend.** When ``VITE_AUTH_ENABLED=true`` (set by the overlay) the SPA
mounts ``react-oidc-context``, redirects unauthenticated users to Keycloak via
PKCE, and gates the app until login completes. The current route is preserved as
OIDC ``state`` and restored after login (deep-link). An avatar/name dropdown
provides logout. The access token is read from ``oidc-client-ts`` storage and
attached to every API request through the shared axios client.

**Backend.** With ``TRACEPCAP_AUTH_ENABLED=true`` the API runs as a stateless
OAuth2 resource server: ``/api`` is gated behind a Keycloak JWT. The
``JwtDecoder`` validates the token issuer against the public ``PUBLIC_URL`` but
fetches JWKS from the **internal** Keycloak host
(``http://keycloak:8080/...``), decoupling key retrieval from issuer validation
inside Docker. Issuer validation is fail-closed — a missing or mismatched issuer
is rejected.

HTTPS / TLS
-----------

Keycloak runs in ``start-dev`` mode (HTTP, no TLS) for offline use or where TLS
is terminated by an upstream reverse proxy. nginx strips Keycloak's HSTS header
so it cannot poison a plain-HTTP origin into HTTPS-only. For internet-facing
deployments, terminate TLS in front of nginx and set ``PUBLIC_URL`` to the
``https://`` origin. See :doc:`../operations/production-hardening`.

Related environment variables
-----------------------------

See :doc:`environment-variables` for ``PUBLIC_URL``,
``TRACEPCAP_AUTH_ENABLED``, ``KEYCLOAK_ADMIN``, and
``KEYCLOAK_ADMIN_PASSWORD``. The ``KEYCLOAK_ISSUER_URI``,
``KEYCLOAK_JWK_SET_URI``, and ``VITE_AUTH_*`` values are set automatically by
the overlay and derived from ``PUBLIC_URL``.
