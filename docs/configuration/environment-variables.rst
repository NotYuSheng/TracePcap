Environment Variables
=====================

All configuration is driven by environment variables defined in the ``.env``
file at the repository root. Copy ``.env.example`` to ``.env`` before starting.

Upload Configuration
--------------------

.. list-table::
   :header-rows: 1
   :widths: 35 15 50

   * - Variable
     - Default
     - Description
   * - ``MAX_UPLOAD_SIZE_BYTES``
     - ``536870912``
     - Maximum PCAP file size in bytes (default 512 MB). Applies to both the
       Spring Boot backend and the nginx reverse proxy.

Nginx Configuration
-------------------

.. list-table::
   :header-rows: 1
   :widths: 35 15 50

   * - Variable
     - Default
     - Description
   * - ``NGINX_PORT``
     - ``80``
     - Host port on which nginx listens. Change if port 80 is already in use.

LLM Configuration
-----------------

.. list-table::
   :header-rows: 1
   :widths: 35 15 50

   * - Variable
     - Default
     - Description
   * - ``LLM_API_BASE_URL``
     - ``http://localhost:1234/v1``
     - Base URL of an OpenAI-compatible inference API. See
       :doc:`llm-setup`.
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
     - ``2000``
     - Maximum number of tokens the LLM may generate per response.

Map Configuration
-----------------

.. list-table::
   :header-rows: 1
   :widths: 35 15 50

   * - Variable
     - Default
     - Description
   * - ``MAP_POLYGON_FIDELITY``
     - *(auto)*
     - Controls the detail level of country/region polygon boundaries rendered
       on the map view. Higher values increase visual fidelity at the cost of
       browser rendering time.

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
