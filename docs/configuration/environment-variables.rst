Environment Variables
=====================

All configuration is driven by environment variables defined in the ``.env``
file at the repository root. Copy ``.env.example`` to ``.env`` before starting.

Memory & Upload
---------------

Upload limits are **derived from a single memory budget** rather than set
directly. Set ``APP_MEMORY_MB`` and everything else scales automatically.

.. list-table::
   :header-rows: 1
   :widths: 35 15 50

   * - Variable
     - Default
     - Description
   * - ``APP_MEMORY_MB``
     - ``2048``
     - Total RAM (in MB) allocated to the backend container — the default for
       the enforced container memory limit and the budget for derived settings.
       All derived values use the *effective* budget (the enforced cgroup limit
       when one is set, else this value): JVM heap = 50%, max upload size = 25%,
       nginx body limit = max upload + 50 MB multipart buffer, and the
       proxy/analysis timeout scales with memory (300–900 s). Examples:
       ``2048`` → 512 MB max upload
       (default), ``4096`` → 1 GB, ``8192`` → 2 GB. The heap is 50% rather than
       75% because tshark/ndpi/Suricata allocate outside the JVM heap — see
       :doc:`../operations/production-hardening`.
   * - ``BACKEND_MEM_LIMIT``
     - ``APP_MEMORY_MB``
     - Enforced backend container memory limit. Tracks ``APP_MEMORY_MB`` by
       default. When set explicitly it becomes the **effective budget**: the JVM
       heap, max upload size and analysis timeout are all derived from it rather
       than from ``APP_MEMORY_MB``, keeping the 50%/25% split coherent at any
       cap. Setting it lower therefore also lowers the max upload size.
   * - ``BACKEND_CPU_LIMIT``
     - ``4``
     - Backend CPU limit. Analysis is subprocess-heavy and parallel, so the
       backend is sized above the other services.
   * - ``POSTGRES_MEM_LIMIT`` / ``POSTGRES_CPU_LIMIT``
     - ``1g`` / ``2``
     - Postgres container limits.
   * - ``MINIO_MEM_LIMIT`` / ``MINIO_CPU_LIMIT``
     - ``1g`` / ``2``
     - MinIO container limits.
   * - ``NGINX_MEM_LIMIT`` / ``NGINX_CPU_LIMIT``
     - ``256m`` / ``1``
     - nginx container limits. Request bodies larger than
       ``client_body_buffer_size`` spill to disk rather than RAM, so nginx needs
       far less memory than the max upload size (but does need scratch space in
       ``/tmp``).
   * - ``KEYCLOAK_MEM_LIMIT`` / ``KEYCLOAK_CPU_LIMIT``
     - ``1g`` / ``2``
     - Keycloak container limits (auth overlays only).

Feature Toggles
---------------

Every switch that turns a capability on or off, in one place. Each is also
documented in its own section below with the surrounding detail.

.. list-table::
   :header-rows: 1
   :widths: 34 12 54

   * - Variable
     - Default
     - Effect
   * - ``TRACEPCAP_AUTH_ENABLED``
     - ``false``
     - Gates the API behind a Keycloak JWT and adds a login flow. Set to
       ``true`` by the production overlays; you rarely set it directly. See
       :doc:`authentication`.
   * - ``SURICATA_ENABLED``
     - ``true``
     - Deployment-wide switch for intrusion-detection enrichment. ``false``
       skips it for **every** capture regardless of the per-upload toggle.
       Adds ~50 s of fixed rule-loading overhead to each capture it processes,
       on top of packet scanning that scales with size. The fixed floor makes it the
       biggest throughput lever, and proportionally heaviest on small captures.
   * - ``FILE_RETENTION_ENABLED``
     - ``true``
     - Master switch for automatic deletion. ``false`` keeps captures
       indefinitely and the clean-up scheduler is never registered, so no other
       retention setting has any effect. See :doc:`../operations/production-hardening`.
   * - ``STUCK_FILE_RECONCILIATION_ENABLED``
     - ``true``
     - Scheduled job that flips captures stranded in ``PROCESSING`` to
       ``FAILED`` after a timeout. Disabling it leaves crashed or
       restart-interrupted analyses stuck indefinitely.
   * - ``GEO_ENRICHMENT_ENABLED``
     - ``true``
     - Turns geolocation enrichment off entirely — no lookups, no bundled-database
       resolution, no geo fields on hosts. Distinct from ``GEO_FORCE_OFFLINE``,
       which keeps enrichment but stops it reaching the network.
   * - ``GEO_FORCE_OFFLINE``
     - ``false`` / ``true``
     - Suppresses the ``ipinfo.io`` connectivity probe and lookups, resolving
       geolocation from the bundled database only. Defaults to ``false`` in the
       base stack and ``true`` in the offline stack and both production
       overlays. This is the one intentional outbound call at runtime.

.. note::

   These are **deployment-wide**. Several analysis features also have per-upload
   toggles in the UI (nDPI, Suricata, file extraction) which apply to a single
   capture. Where both exist the deployment-wide switch wins: turning Suricata
   off here skips it even for an upload that requested it.

.. note::

   Two capabilities are switched by configuration rather than a boolean. AI
   features are governed by ``LLM_API_BASE_URL`` — point it at a reachable local
   inference server to enable them; the production overlays require it to be set
   explicitly. Custom detection rules activate when a signatures file is present.

File Retention
--------------

Retention is **entirely opt-out**. To keep everything indefinitely — the usual
choice for air-gapped or evidence-preservation deployments — set:

.. code-block:: ini

   FILE_RETENTION_ENABLED=false

That is sufficient on its own, and it is the **master switch**: the cleanup
scheduler is not registered at all, so none of the settings below do anything
while it is ``false``.

.. danger::

   ``0`` does **not** mean "never" for ``FILE_RETENTION_HOURS``. It means *delete
   every analysis file immediately* — an expiry cutoff of "now" — and the next
   hourly sweep will remove them all.

   ``0`` means "never" only for ``MONITOR_FILE_RETENTION_HOURS`` and
   ``PACKET_RETENTION_HOURS``, which are explicitly guarded against zero. To
   disable deletion, use ``FILE_RETENTION_ENABLED=false``; never
   ``FILE_RETENTION_HOURS=0``.

Deletion is only ever triggered by these settings; nothing else in the
application removes captures or packets on its own.

.. list-table::
   :header-rows: 1
   :widths: 35 15 50

   * - Variable
     - Default
     - Description
   * - ``FILE_RETENTION_ENABLED``
     - ``true``
     - Set to ``false`` to keep uploaded files indefinitely and disable the
       automatic cleanup scheduler entirely. Useful for air-gapped or
       long-term-audit deployments where evidence preservation is required.
   * - ``FILE_RETENTION_HOURS``
     - ``12``
     - Number of hours after upload before an analysis file is automatically
       deleted (only applies when ``FILE_RETENTION_ENABLED=true``). **Not
       zero-guarded** — ``0`` deletes everything immediately; see the warning
       above. Monitor Network files are exempt and use
       ``MONITOR_FILE_RETENTION_HOURS`` instead.
   * - ``MONITOR_FILE_RETENTION_HOURS``
     - ``0``
     - Number of hours before a **monitor-mode snapshot** file is deleted;
       ``0`` (the default) means **never**. Monitor networks are a time series,
       so expiring their snapshots destroys the drift history that makes them
       useful — which is why they are exempt from ``FILE_RETENTION_HOURS``.
       Monitor mode is consequently where unbounded growth accumulates on a
       long-lived deployment.

       .. warning::

          Setting a non-zero value here is **not currently recommended**.
          Scheduled cleanup deletes the file directly, bypassing the snapshot
          re-ordering and change-detection replay that removing a snapshot
          through the UI performs, which leaves gaps in ``snapshot_order`` and
          orphaned change events. Prune monitor snapshots through the UI until
          `issue #635 <https://github.com/NotYuSheng/TracePcap/issues/635>`_ is
          resolved.
   * - ``PACKET_RETENTION_HOURS``
     - ``0``
     - Number of hours after upload before a file's **raw packets** are pruned,
       while the file keeps its conversations and analysis results (``0`` = packets
       live as long as the file). Packets dominate database size (~1.5–2M rows per
       GB of PCAP), so setting this below ``FILE_RETENTION_HOURS`` reclaims most of
       the storage early at the cost of packet-level drill-down. Pruning drops the
       file's ``packets`` partition outright, so it is O(1) regardless of size.

Analysis Queue & Reconciliation
-------------------------------

Uploaded files are analyzed asynchronously by an in-memory thread pool. Analysis
is **Suricata-dominated**: for every capture Suricata processes it adds roughly
**50 s of fixed overhead**, because the full rule set is reloaded on each
invocation. Packet scanning on top of
that still scales with capture size, so total analysis time grows — but the 50 s
floor is paid even by a tiny capture. Throughput is CPU-bound. When the
pool and its queue are both full the executor applies **back-pressure**: the
upload request runs the analysis inline and slows down, rather than dropping the
file. A reconciliation job additionally flips any file left stuck in
``PROCESSING`` past a timeout to ``FAILED`` (covering crashes and restarts, since
the queue is in-memory and lost on restart).

**Sizing guidance:** keep ``ASYNC_MAX_POOL_SIZE`` at or below the host CPU core
count to avoid CPU contention between concurrent Suricata runs. Raise
``ASYNC_QUEUE_CAPACITY`` to absorb larger bursts before back-pressure kicks in.
For a 24-core box, ``ASYNC_MAX_POOL_SIZE=20`` (leaving headroom for the JVM, DB,
and MinIO) with a queue of a few hundred is a reasonable starting point.

.. list-table::
   :header-rows: 1
   :widths: 40 12 48

   * - Variable
     - Default
     - Description
   * - ``ASYNC_CORE_POOL_SIZE``
     - ``5``
     - Number of threads kept alive to run analyses. These stay up even when
       idle.
   * - ``ASYNC_MAX_POOL_SIZE``
     - ``10``
     - Maximum analysis threads. Keep at or below the host CPU core count —
       analysis is CPU-bound (Suricata), so oversubscribing degrades throughput.
   * - ``ASYNC_QUEUE_CAPACITY``
     - ``100``
     - Files that may wait in the in-memory queue once all threads are busy.
       Once the queue is also full, uploads apply back-pressure (run analysis
       inline). This queue is **not** persisted — pending work is lost on
       restart and recovered as ``FAILED`` by reconciliation.
   * - ``STUCK_FILE_RECONCILIATION_ENABLED``
     - ``true``
     - Set to ``false`` to disable the scheduled job that flips files stuck in
       ``PROCESSING`` to ``FAILED``.
   * - ``STUCK_FILE_TIMEOUT_MINUTES``
     - ``30``
     - Minutes a file may stay in ``PROCESSING`` before reconciliation marks it
       ``FAILED``. Must exceed the longest expected analysis time so healthy
       in-flight jobs are never killed.
   * - ``SURICATA_ENABLED``
     - ``true``
     - Deployment-wide kill-switch for Suricata IDS enrichment. Set to
       ``false`` to skip Suricata for **every** file regardless of the per-file
       upload toggle. On each capture it processes it adds ~50 s of fixed overhead —
       the rule set is reloaded each time — plus packet scanning that does scale
       with size. On a
       538 KB test capture the fixed floor alone was ~94% of total analysis time;
       on a large capture it is a much smaller share.

Nginx
-----

.. list-table::
   :header-rows: 1
   :widths: 35 15 50

   * - Variable
     - Default
     - Description
   * - ``NGINX_PORT``
     - ``80``
     - Host port on which nginx listens. Change if port 80 is already in use.

Public Origin & Authentication
------------------------------

These variables apply only when running with the production overlay that
enables OIDC/Keycloak authentication. See :doc:`authentication` for the full
walkthrough. They are ignored by the base stack.

.. list-table::
   :header-rows: 1
   :widths: 35 25 40

   * - Variable
     - Default
     - Description
   * - ``PUBLIC_URL``
     - ``http://localhost:8888``
     - The exact origin you browse to (scheme + host + port). Pins Keycloak's
       token issuer and the backend's issuer check, so the browser must load
       the app via this same origin. Include the port only if non-standard
       (e.g. ``:8888``); omit for standard 80/443. **Does not track**
       ``NGINX_PORT`` — set it to match your actual port.
   * - ``TRACEPCAP_AUTH_ENABLED``
     - ``false``
     - Backend toggle. When ``false`` (default, base stack) the API is
       permit-all. The prod overlay sets this to ``true`` to gate ``/api``
       behind a Keycloak JWT.
   * - ``KEYCLOAK_ADMIN``
     - *(none)*
     - Keycloak bootstrap admin username (admin console is served same-origin
       at ``/admin``). **Required** — the production overlays abort if unset.
   * - ``KEYCLOAK_ADMIN_PASSWORD``
     - *(none)*
     - Keycloak bootstrap admin password. **Required** — the production overlays
       abort if unset. See :doc:`../operations/production-hardening`.

.. note::
   ``KEYCLOAK_ISSUER_URI``, ``KEYCLOAK_JWK_SET_URI``, and the ``VITE_AUTH_*``
   build args are set automatically by ``docker-compose.prod.yml`` and derived
   from ``PUBLIC_URL`` — you normally do not set them by hand.

Spring Profile & CORS
---------------------

The active Spring profile selects dev vs. hardened behaviour. The two
``*-prod.yml`` overlays set ``SPRING_PROFILES_ACTIVE=prod``; the base stacks
run ``dev``. See :doc:`../operations/production-hardening` for the full profile
matrix.

.. list-table::
   :header-rows: 1
   :widths: 35 25 40

   * - Variable
     - Default
     - Description
   * - ``SPRING_PROFILES_ACTIVE``
     - ``dev`` (base) / ``prod`` (``*-prod.yml`` overlays)
     - ``prod`` enforces strict CORS, disables Swagger + ``/v3/api-docs``,
       suppresses stacktraces/exception details in error responses, and logs at
       WARN to a file.
   * - ``CORS_ALLOWED_ORIGINS``
     - dev: localhost list / prod: *(empty)*
     - Comma-separated allowed browser origins for ``/api``. Under ``prod`` it
       has **no localhost defaults**; leave it empty for the same-origin shipped
       stack (nginx proxies ``/api``, so CORS is never exercised). Set it only
       when the frontend is hosted on a different origin from the API.
   * - ``LOG_DIR``
     - ``/app/logs``
     - Directory for the ``prod`` profile's ``application.log`` (created and
       owned by the container's non-root user at startup). Ignored under ``dev``
       (console-only logging).

LLM
---

.. list-table::
   :header-rows: 1
   :widths: 35 25 40

   * - Variable
     - Default
     - Description
   * - ``LLM_API_BASE_URL``
     - ``http://localhost:1234/v1``
     - Base URL of an OpenAI-compatible inference API. See :doc:`llm-setup`.
   * - ``LLM_API_KEY``
     - *(empty)*
     - API key sent in the ``Authorization: Bearer`` header. Leave empty for
       local servers that don't require authentication.
   * - ``LLM_MODEL``
     - ``Qwen2.5-14B-Coder-Instruct``
     - Model identifier passed in each API request. Must match a model loaded
       on your inference server.
   * - ``LLM_TEMPERATURE``
     - ``0.7``
     - Sampling temperature (0.0–2.0). Lower values produce more deterministic
       output; higher values more creative output.
   * - ``LLM_MAX_TOKENS``
     - ``8000``
     - Maximum number of tokens the LLM may generate per response. Controls
       response length only — not the context window. Increase if stories are
       cut off; decrease to save compute. Recommended 4000–8000.
   * - ``LLM_CONTEXT_LENGTH``
     - *(auto)*
     - The context window size (in tokens) configured on your LLM server. Used
       to detect prompt-too-large errors early. If unset, auto-detected from
       the ``/v1/models`` endpoint; if that fails, the configured
       ``LLM_MAX_TOKENS`` value remains in effect. Example: ``32768`` for a 32k
       model.
   * - ``LLM_TIMEOUT``
     - ``300``
     - HTTP timeout in seconds for LLM API requests. Local models can be slow —
       increase if you get timeout errors.

Overview Applications
---------------------

.. list-table::
   :header-rows: 1
   :widths: 35 15 50

   * - Variable
     - Default
     - Description
   * - ``OVERVIEW_APPS_LIMITED``
     - ``true``
     - Cap the number of detected applications shown in the overview. Set to
       ``false`` to show all detected applications regardless of count.
   * - ``OVERVIEW_APPS_MAX``
     - ``100``
     - Maximum detected applications shown in the overview when
       ``OVERVIEW_APPS_LIMITED=true`` (ranked alphabetically).

File Extraction
---------------

Tunes the limits applied when extracting embedded files from captures. When any
limit is hit, a warning is shown on the Extracted Files tab. See
:doc:`../features/file-extraction`.

.. list-table::
   :header-rows: 1
   :widths: 40 12 48

   * - Variable
     - Default
     - Description
   * - ``EXTRACTION_MAX_MATCHES_PER_STREAM``
     - ``20``
     - Max files extracted from a single raw TCP/UDP stream. Guards against
       runaway extraction on streams with many magic-byte sequences.
   * - ``EXTRACTION_MAX_STREAM_CONVERSATIONS``
     - ``50``
     - Max number of non-HTTP streams scanned for embedded files per PCAP.
   * - ``EXTRACTION_MAX_FILE_SIZE_MB``
     - ``50``
     - Max size (MB) of a single extracted file that will be stored. Larger
       files are detected but skipped (shown with a "Too large" badge).

Frontend (build-time)
---------------------

``VITE_*`` variables are baked in at build time, so changing them requires a
rebuild (``docker compose up -d --build``).

.. list-table::
   :header-rows: 1
   :widths: 40 22 38

   * - Variable
     - Default
     - Description
   * - ``VITE_MAP_RESOLUTION``
     - ``50m``
     - Polygon fidelity of the world map. ``110m`` (~170 KB, low-resource),
       ``50m`` (default, ~760 KB), or ``10m`` (~1 MB, high-fidelity coastline).
   * - ``VITE_SUPPORTED_FILE_TYPES``
     - ``.pcap,.pcapng,.cap``
     - Comma-separated list of accepted upload extensions.
   * - ``VITE_NETWORK_DIAGRAM_CONVERSATION_LIMIT``
     - ``false``
     - Toggles the 500-conversation rendering cap in the Network Topology
       Diagram. Set ``true`` to **enable** the cap (render at most 500
       conversations). The shipped ``.env.example`` default is ``false``, which
       **disables** the cap and loads every conversation — this may cause
       browser slowdowns or out-of-memory errors on large captures.
   * - ``APP_VERSION``
     - ``dev``
     - Version string rendered in the app footer (passed as the
       ``VITE_APP_VERSION`` build arg). In CI this is set from
       ``git describe --tags``.

Database Configuration (internal)
----------------------------------

The following variables configure the PostgreSQL connection. They are set
automatically by Docker Compose and generally do not need to be changed unless
you are connecting to an external database.

.. list-table::
   :header-rows: 1
   :widths: 35 65

   * - Variable
     - Description
   * - ``POSTGRES_DB``
     - Database name
   * - ``POSTGRES_USER``
     - Database user
   * - ``POSTGRES_PASSWORD``
     - Database password — **change this in production**. The backend's
       ``DATABASE_PASSWORD`` is derived from this value in the compose files, so
       the two cannot drift apart; there is no separate variable to set.

MinIO Configuration (internal)
-------------------------------

.. list-table::
   :header-rows: 1
   :widths: 35 65

   * - Variable
     - Description
   * - ``MINIO_ROOT_USER``
     - MinIO admin username (default ``minioadmin``) — **change in production**
   * - ``MINIO_ROOT_PASSWORD``
     - MinIO admin password (default ``minioadmin``) — **change in production**
