Production Hardening
=====================

The default TracePcap configuration is optimised for quick local testing.
Before exposing the application to a wider audience, follow these steps.

Spring Profile per Deployment Mode
----------------------------------

The backend selects behaviour via ``SPRING_PROFILES_ACTIVE``:

.. list-table::
   :header-rows: 1
   :widths: 40 20 40

   * - Compose invocation
     - Profile
     - Notes
   * - ``docker-compose.yml`` (base)
     - ``dev``
     - Open quick-start / Lanturn. Swagger on, verbose errors, localhost CORS
       defaults, DEBUG logging.
   * - ``docker-compose.offline.yml``
     - ``dev``
     - Air-gapped quick-start. Same dev defaults as the base file.
   * - ``… -f docker-compose.prod.yml``
     - ``prod``
     - Auth overlay. Strict CORS, Swagger + ``/v3/api-docs`` disabled,
       stacktraces/exception details suppressed, WARN logging to file.
   * - ``… -f docker-compose.offline-prod.yml``
     - ``prod``
     - Offline auth overlay. Same ``prod`` hardening as above.

The two ``*-prod.yml`` overlays set ``SPRING_PROFILES_ACTIVE=prod`` on the
backend, overriding the base file's ``dev``. This is the intended production
path — enabling authentication (below) and the ``prod`` profile together.

Under the ``prod`` profile CORS defaults to **empty** (no localhost origins).
The shipped stack is same-origin — nginx serves the SPA and proxies ``/api`` on
one origin — so browser→API calls never trigger CORS and no origins need
allowing. Set ``CORS_ALLOWED_ORIGINS`` (comma-separated) **only** if you host
the frontend on a different origin from the API.

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

Container Resource Limits
-------------------------

Every service declares CPU and memory limits via ``deploy.resources.limits``.
Without them a single large capture can exhaust host memory and take the whole
box down with it.

Why the backend is the one that matters
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The backend does **not** do its packet work inside the JVM. It shells out to
native subprocesses — ``tshark``, ``ndpi``, ``Suricata``, ``tcpflow`` — whose
memory lives entirely *outside* the JVM heap. A container budget therefore has
to cover three things, not one:

.. list-table::
   :header-rows: 1
   :widths: 30 15 55

   * - Consumer
     - Share
     - Notes
   * - JVM heap
     - ~50%
     - ``-Xmx``/``MaxRAMPercentage``; pre-committed at startup.
   * - JVM non-heap
     - ~20%
     - Metaspace, thread stacks, code cache, direct buffers (~250–400 MB).
   * - Native subprocesses
     - ~30%
     - ``tshark``/``ndpi``/``Suricata``; scales with capture size.

This is why the heap is **50%** of the budget rather than the 75% used before
issue #378. At 75% there was no room left for the native half of the workload;
once a hard memory limit exists, that overflow becomes an immediate OOM-kill of
the backend container instead of a diffuse host-level memory problem.

How the heap is sized
~~~~~~~~~~~~~~~~~~~~~

``backend/docker-entrypoint.sh`` reads the **enforced cgroup limit** and sets the
heap to 50% of it via ``-XX:MaxRAMPercentage``. It does not simply trust
``APP_MEMORY_MB``. This matters because the JVM then sizes itself against the
limit the kernel will actually enforce, even if the compose limit and
``APP_MEMORY_MB`` have drifted apart. When the container runs with no memory
limit at all, it falls back to computing ``-Xms``/``-Xmx`` from ``APP_MEMORY_MB``.

The startup banner reports which path was taken::

   TracePcap backend starting:
     APP_MEMORY_MB        = 2048 MB
     Memory budget from   = cgroup limit (2048 MB)
     JVM heap             = 1024 MB (50% of budget)
     Native headroom      = 50% for JVM non-heap + tshark/ndpi/Suricata

Sizing
~~~~~~

``BACKEND_MEM_LIMIT`` defaults to ``APP_MEMORY_MB``, so raising the latter raises
the enforced limit in step and the two cannot silently diverge.

.. list-table::
   :header-rows: 1
   :widths: 18 16 16 16 34

   * - Service
     - Minimum
     - Default
     - CPU
     - Notes
   * - backend
     - 2 GB
     - 2 GB
     - 4
     - Raise via ``APP_MEMORY_MB``. 4 GB+ recommended for captures >100 MB or
       with ``SURICATA_ENABLED=true``.
   * - postgres
     - 512 MB
     - 1 GB
     - 2
     - Grows with retained analysis history.
   * - minio
     - 512 MB
     - 1 GB
     - 2
     - Streams objects; not upload-size bound.
   * - nginx
     - 128 MB
     - 256 MB
     - 1
     - Streams uploads rather than buffering them whole.
   * - keycloak
     - 512 MB
     - 1 GB
     - 2
     - Auth overlays only.

Totals ``~5.4 GB`` for the default stack, ``~6.4 GB`` with an auth overlay.

Every value is overridable, e.g. for a 4-core / 8 GB host:

.. code-block:: ini

   APP_MEMORY_MB=4096      # backend budget + enforced limit, 2 GB heap
   BACKEND_CPU_LIMIT=3
   POSTGRES_MEM_LIMIT=1g
   MINIO_MEM_LIMIT=512m

.. note::

   ``deploy.resources.limits`` is honoured by ``docker compose up`` — it is not
   Swarm-only. ``deploy.resources.reservations`` (CPU/memory *requests*) **is**
   Swarm/Kubernetes-only and is deliberately not used here; requests are a
   scheduling concept with no meaning on a single Compose host.

Restart Policies
----------------

All long-running services set ``restart: unless-stopped`` so a crashed container
comes back automatically and the stack survives a host reboot. The ``minio-init``
bucket-bootstrap job is deliberately excluded — it is meant to run once and exit
``0``, and a restart policy would loop it forever.

To stop a service and have it *stay* stopped, use ``docker compose stop <svc>``;
``unless-stopped`` honours a manual stop across daemon restarts.

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
