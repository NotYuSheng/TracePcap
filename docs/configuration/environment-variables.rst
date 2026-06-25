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
     - Total RAM (in MB) allocated to the backend container. Derived
       automatically from this value: JVM heap = 75%, max upload size = 25%,
       nginx body limit = max upload + 50 MB multipart buffer, and the
       proxy/analysis timeout scales with memory (300–900 s). Examples:
       ``2048`` → 512 MB max upload (default), ``4096`` → 1 GB, ``8192`` → 2 GB.

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
   * - ``VITE_ANALYSIS_OPTIONS``
     - ``false``
     - Set to ``true`` to show the pre-upload analysis options modal.
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
