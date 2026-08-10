Production Hardening
=====================

The default TracePcap configuration is optimised for quick local testing.
Before exposing the application to a wider audience, follow these steps.

Checklist
---------

Any deployment beyond local development must:

- Override **all** sample credentials — PostgreSQL, MinIO, and the Keycloak admin.
- Restrict exposed services so PostgreSQL and MinIO are not externally reachable.
- Terminate **TLS** at nginx.
- Set explicit ``CORS_ALLOWED_ORIGINS`` if the frontend is served from a
  different origin than the API.
- Point the LLM at a **local inference server**, so capture-derived content is
  never sent to a third party.
- Enable authentication via the Keycloak overlay where the deployment is shared.
- **Choose a retention window.** The default deletes captures after 12 hours.
- **Confirm disk headroom** against that window, with room for backups.
- **Install the backup timer.** Nothing is backed up until you do.

Each is covered in detail below.

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
     - Open quick-start. Swagger on, verbose errors, localhost CORS
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

nginx serves plain HTTP by default. Everything the browser sends — including the
sign-on token once authentication is enabled — crosses the network unencrypted
until you terminate TLS.

.. note::

   The config is **baked into the nginx image** at build time
   (``nginx/nginx.conf.template``) and rendered by ``envsubst`` at container
   start. Editing the running container's ``/etc/nginx/nginx.conf`` does not
   survive a restart. Use one of the two routes below.

Step 1 — obtain a certificate
   From your internal CA for a private deployment, or Let's Encrypt if the host is
   internet-reachable. You need the certificate chain and the private key, e.g.
   ``fullchain.pem`` and ``privkey.pem``.

Step 2 — mount the certificate and publish 443
   Add to the ``nginx`` service. Keep the key read-only, and note it must be
   readable by the nginx worker user inside the container.

   .. code-block:: yaml

      services:
        nginx:
          ports:
            - "${NGINX_PORT:-80}:80"
            - "443:443"
          volumes:
            - ./certs/fullchain.pem:/etc/nginx/certs/fullchain.pem:ro
            - ./certs/privkey.pem:/etc/nginx/certs/privkey.pem:ro

Step 3 — add the HTTPS server block
   Edit ``nginx/nginx.conf.template``. Change the existing ``server`` block to
   listen on 443 with TLS, and add a redirect for plain HTTP. Keep every existing
   ``location`` block — they proxy ``/api`` and, under the auth overlay, the
   sign-on paths.

   .. code-block:: nginx

      server {
          listen 80;
          server_name _;
          return 301 https://$host$request_uri;
      }

      server {
          listen 443 ssl;
          http2 on;
          server_name _;

          ssl_certificate     /etc/nginx/certs/fullchain.pem;
          ssl_certificate_key /etc/nginx/certs/privkey.pem;
          ssl_protocols       TLSv1.2 TLSv1.3;
          ssl_ciphers         HIGH:!aNULL:!MD5;
          ssl_session_cache   shared:SSL:10m;

          add_header Strict-Transport-Security "max-age=31536000" always;

          # ... keep the existing location blocks unchanged ...
      }

   Rebuild so the change lands in the image:

   .. code-block:: bash

      docker compose up -d --build nginx

   **Offline deployments** run a pre-built image and cannot rebuild on the target
   host. Either bake the change in when you build the image bundle, or bind-mount
   a finished config over the rendered one:

   .. code-block:: yaml

      volumes:
        - ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro

   A bind-mount bypasses ``envsubst``, so substitute ``${NGINX_MAX_BODY_SIZE}``
   and ``${NGINX_PROXY_TIMEOUT}`` with literal values first, or the upload limit
   and proxy timeout will be wrong.

Step 4 — update the public origin
   With the authentication overlay, ``PUBLIC_URL`` pins the token issuer and the
   backend's issuer check. It must match the origin the browser actually loads,
   scheme included:

   .. code-block:: ini

      PUBLIC_URL=https://app.example.com

   Getting this wrong fails the redirect or the issuer check rather than falling
   back gracefully. Recreate Keycloak after changing it. See
   :doc:`../configuration/authentication`.

Step 5 — verify
   .. code-block:: bash

      curl -sI https://app.example.com | head -1        # expect 200
      curl -sI http://app.example.com  | head -1        # expect 301

   Confirm the redirect lands on the same host you set in ``PUBLIC_URL``, then log
   in once end to end — a mismatch usually surfaces at the sign-on redirect rather
   than at the first page load.

.. tip::

   If a reverse proxy, load balancer or Tailscale already terminates TLS in front
   of this host, leave nginx on HTTP and set ``PUBLIC_URL`` to the external
   ``https://`` origin instead. The stack trusts ``X-Forwarded-*`` from the proxy.

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

Plan Storage & Retention
------------------------

Container limits bound memory and CPU. Disk is bounded by **retention**, and it is
the one resource the stack will happily consume until it runs out — which takes
the service down and breaks the next backup with it.

.. danger::

   The shipped default deletes analysis captures **after 12 hours**. That is
   deliberate for local testing and wrong for most real deployments. Decide the
   window before go-live rather than discovering it when a capture disappears.

Step 1 — choose a retention window
   Set these in ``.env``. See :doc:`../configuration/environment-variables` for
   the full table.

   .. code-block:: ini

      FILE_RETENTION_ENABLED=true    # false keeps everything, forever
      FILE_RETENTION_HOURS=12        # analysis captures
      MONITOR_FILE_RETENTION_HOURS=0 # monitor snapshots; 0 = never expire
      PACKET_RETENTION_HOURS=0       # 0 = packets live as long as the capture

   For **evidence preservation or air-gapped audit work**, set
   ``FILE_RETENTION_ENABLED=false``. That alone is sufficient — the clean-up
   scheduler is then never registered, so nothing below it can delete anything.

   .. warning::

      ``0`` means "never" only for ``MONITOR_FILE_RETENTION_HOURS`` and
      ``PACKET_RETENTION_HOURS``. For ``FILE_RETENTION_HOURS`` it means *delete
      everything now*. To disable deletion use ``FILE_RETENTION_ENABLED=false``,
      never ``FILE_RETENTION_HOURS=0``.

Step 2 — size the disk against that window
   Storage runs to roughly **2.5x the capture volume ingested** — the objects
   themselves plus a database of comparable size. With retention on, the working
   set stops growing:

   .. code-block:: text

      steady state  ~=  ingest_per_day  x  2.5  x  (FILE_RETENTION_HOURS / 24)

   So 20 GB of captures a week (~2.9 GB/day) at the default 12-hour window holds
   about **3.6 GB**. With ``FILE_RETENTION_ENABLED=false`` there is no steady
   state and the disk is the only limit — size it for the full retained corpus.
   :doc:`scalability` works both directions, including the disk-to-window inverse.

Step 3 — leave headroom for backups
   ``scripts/backup.sh`` stages an uncompressed copy before archiving, so a run
   needs roughly **twice the live data set** free. A full disk breaks backups at
   exactly the moment they matter.

Step 4 — check it, and keep checking
   .. code-block:: bash

      bash scripts/capacity.sh

   Reports current usage and projects when the disk fills, from the observed
   ingest rate. It is read-only and safe on a live deployment; the exit code makes
   it usable as a cron canary. See :doc:`scalability` for thresholds.

.. note::

   **Monitor snapshots do not expire by default.** They are exempt from
   ``FILE_RETENTION_HOURS`` because a monitor network is a time series and
   expiring its snapshots destroys the drift history. On a monitor-heavy
   deployment they are therefore the component that actually accumulates — check
   them first when disk grows unexpectedly.

Set Up Backups
--------------

.. danger::

   **No backup runs until you install the timer.** ``scripts/backup.sh`` is a
   standalone script — it is not wired into Docker Compose, the application, or
   any scheduler. A fresh deployment has no backups at all, however long it has
   been running.

The scripts and unit files ship in ``scripts/``; installing them is a deliberate
step:

.. code-block:: bash

   sudo cp scripts/tracepcap-backup.service scripts/tracepcap-backup.timer \
     /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable --now tracepcap-backup.timer

Edit ``User``, ``WorkingDirectory`` and ``BACKUP_DIR`` in the ``.service`` file
first so they match this deployment. Then confirm it is actually scheduled —
copying the files is not enough on its own:

.. code-block:: bash

   systemctl list-timers tracepcap-backup.timer

Point ``BACKUP_DIR`` at storage on a **different disk** from the deployment. A
backup on the same disk does not survive that disk failing, which is the main
thing it exists for.

.. important::

   Rehearse the restore before the deployment holds data you care about. An
   untested backup is not a backup, and the restore is the one procedure you do
   not want to be performing for the first time during an incident. The rehearsal
   is a documented five-step drill in :doc:`backup-restore`.

Full detail — what is captured, recovery objectives, the cron alternative, and
what is deliberately *not* covered — is in :doc:`backup-restore`.

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
