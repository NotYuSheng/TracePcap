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

Credentials come from ``.env`` — there is no need to edit any compose file.

The base stack defaults them to well-known development values
(``tracepcap_pass``, ``minioadmin``) so a local or CI run works with no ``.env``.
**Those defaults are public.** The two ``*-prod.yml`` overlays therefore *require*
every credential and abort before starting anything if one is unset.

.. important::

   That check tests only that a value is **present**, not that it is a good one.
   Nothing stops an operator writing ``tracepcap_pass`` or ``minioadmin`` into
   ``.env`` — the overlay would start normally. Replace every value below with a
   unique secret; the fail-fast only catches the case where you forgot.

Set all of these in ``.env`` (see ``.env.example`` for the full list):

.. code-block:: ini

   # First start only — see the warning below before changing these on a
   # deployment that already has a database volume.
   POSTGRES_DB=tracepcap
   POSTGRES_USER=tracepcap_user
   POSTGRES_PASSWORD=<strong-unique-value>

   MINIO_ROOT_USER=<strong-unique-value>
   MINIO_ROOT_PASSWORD=<strong-unique-value>   # MinIO requires 8+ characters
   KEYCLOAK_ADMIN=<admin-username>             # auth overlays only
   KEYCLOAK_ADMIN_PASSWORD=<strong-unique-value>

One value feeds every consumer that has to agree on it — the backend, the
Postgres healthcheck, and the MinIO bucket bootstrap — so they cannot drift apart.

.. warning::

   **All three ``POSTGRES_*`` values above are applied only when the database
   volume is first initialised**, including the password. Changing any of them
   against an existing deployment does not update PostgreSQL:

   - ``POSTGRES_USER`` / ``POSTGRES_DB`` — the old role and database remain, the
     backend connects with the new name, and startup fails.
   - ``POSTGRES_PASSWORD`` — the old password stays active and the new one is
     silently ignored. This is the more dangerous case, because the deployment
     looks like it accepted a rotated credential when it did not.

   Set them before first start. To change them afterwards, either recreate the
   volume (destroying existing data — take a backup first, see
   :doc:`backup-restore`) or alter the running database and update ``.env`` to
   match.

   To rotate the password, use ``psql``'s ``\password`` meta-command. It prompts
   for the value and sends it pre-hashed, so the plaintext never reaches your
   shell history, the process list, or the server log:

   .. code-block:: bash

      docker exec -it tracepcap-postgres psql -U <current-user> -d <current-db>

   .. code-block:: text

      \password <user>
      \q

   Then set the same value as ``POSTGRES_PASSWORD`` in ``.env`` and restart the
   backend so it reconnects with the new credential.

Enable Authentication
---------------------

The base stack runs with **no login**. For multi-user or internet-facing
deployments, enable the bundled OIDC/Keycloak authentication via the production
overlay:

.. code-block:: bash

   PUBLIC_URL=https://app.example.com \
     docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build

This gates the API behind a Keycloak JWT and adds a login flow to the frontend.

The Keycloak admin account has **no default** — set ``KEYCLOAK_ADMIN`` and
``KEYCLOAK_ADMIN_PASSWORD`` in ``.env`` (the overlay aborts otherwise). The realm
still seeds a demo **app login** of ``analyst`` / ``analyst``; change it before
exposing the app. See :doc:`../configuration/authentication` for the full
walkthrough.

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

If you do set ``BACKEND_MEM_LIMIT`` explicitly, the **enforced limit wins**: the
heap, the max upload size and the analysis timeout are all derived from it rather
than from ``APP_MEMORY_MB``, and the startup banner reports the mismatch. This
matters because the alternative is unsafe — sizing the upload from a larger
``APP_MEMORY_MB`` while the kernel enforces a smaller cap would let a single
upload consume the whole native headroom this section exists to protect.

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
     - Buffers request bodies, but large ones spill to disk in ``/tmp`` rather
       than RAM — so memory stays flat while upload size grows.
   * - keycloak
     - 512 MB
     - 1 GB
     - 2
     - Auth overlays only.

Totals ``~4.4 GB`` for the default stack, ``~5.4 GB`` with an auth overlay
(including the 128 MB ``minio-init`` bootstrap job).

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

AI features (Story mode, Network Insights) build their prompts from analysed
capture content, so the LLM endpoint is a **data egress path**.

Both production overlays **require** ``LLM_API_BASE_URL`` and abort if it is
unset, rather than falling back to a default — the online overlay would otherwise
inherit ``api.openai.com`` from the base file, and the offline overlay
``localhost``. Point it at a locally-hosted inference server (LM Studio, Ollama,
vLLM):

.. code-block:: bash

   LLM_API_BASE_URL=http://<your-inference-host>:1234/v1

.. warning::

   Use the address of the inference host **as reachable from the backend
   container**. ``localhost`` resolves to the container itself, not to a server
   running on the Docker host or elsewhere on the LAN, so it will fail at request
   time rather than at startup.

Do **not** configure a cloud API endpoint if your PCAP data is sensitive.

The production overlays also default ``GEO_FORCE_OFFLINE`` to ``true``, resolving
geolocation from the bundled DB-IP Lite MMDB instead of probing ``ipinfo.io`` at
runtime. Set ``GEO_FORCE_OFFLINE=false`` only if outbound lookups are acceptable
and the deployment has internet access.

Restrict MinIO Console Access
-------------------------------

The MinIO console is exposed on port ``9001`` by default. Remove or restrict
this port in ``docker-compose.yml`` for production:

.. code-block:: yaml

   # Comment out or remove:
   # ports:
   #   - "9001:9001"
