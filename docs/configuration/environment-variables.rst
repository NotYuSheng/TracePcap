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
     - nginx container limits. It streams uploads rather than buffering them
       whole, so it needs far less than the max upload size.
   * - ``KEYCLOAK_MEM_LIMIT`` / ``KEYCLOAK_CPU_LIMIT``
     - ``1g`` / ``2``
     - Keycloak container limits (auth overlays only).

File Retention
--------------

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
     - Number of hours after upload before a file is automatically deleted
       (only applies when ``FILE_RETENTION_ENABLED=true``). Monitor Network
       files are exempt from automatic deletion by default.

Analysis Queue & Reconciliation
-------------------------------

Uploaded files are analyzed asynchronously by an in-memory thread pool. Analysis
is **Suricata-dominated** (~50 s per file), so throughput is CPU-bound. When the
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
       upload toggle. Suricata dominates per-file analysis cost, so disabling it
       is the single biggest throughput lever.

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
     - ``user``
     - Keycloak bootstrap admin username (admin console is served same-origin
       at ``/admin``). **Change for any real deployment.**
   * - ``KEYCLOAK_ADMIN_PASSWORD``
     - ``P@ssw0rd``
     - Keycloak bootstrap admin password. **Change for any real deployment.**

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
     - Database password — **change this in production**
   * - ``SPRING_DATASOURCE_PASSWORD``
     - Backend database connection password — must match ``POSTGRES_PASSWORD``

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
