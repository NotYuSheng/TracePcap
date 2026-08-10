Prerequisites
=============

Software Requirements
---------------------

.. list-table::
   :header-rows: 1
   :widths: 25 20 55

   * - Software
     - Version
     - Purpose
   * - Docker
     - Latest
     - Container runtime
   * - Docker Compose
     - Latest
     - Multi-container orchestration
   * - LLM Server *(optional)*
     - Any OpenAI-compatible API
     - AI filter generation and Story Mode (e.g. LM Studio, Ollama)

Hardware Requirements
---------------------

All three tiers below size the TracePcap stack **only**. They assume AI features
are either disabled or pointed via ``LLM_API_BASE_URL`` at a separate inference
server on the same local network. TracePcap must function fully offline, so
``LLM_API_BASE_URL`` must never reference a public or internet-hosted API. Running
the LLM on the TracePcap host itself adds to every figure — see the note at the
end of this section.

**Minimum:**

- RAM: 6 GB, with ``SURICATA_ENABLED=false``
- CPU: 4 cores
- Storage: 10 GB (database, PCAP files, object storage)

**Recommended:**

- RAM: 8 GB or more
- CPU: 4+ cores for fast nDPI analysis
- Storage: 50 GB+ for large PCAP collections

**Comfortable** — Suricata enabled, routine work on large captures:

- RAM: 16 GB
- CPU: 8 cores
- Storage: 100 GB+ SSD

At this tier, raise the defaults in ``.env`` — the shipped ``APP_MEMORY_MB=2048``
caps uploads at 512 MB, which is usually the first limit reached:

.. code-block:: ini

   APP_MEMORY_MB=8192      # 4 GB heap, 2 GB max upload
   BACKEND_CPU_LIMIT=6
   POSTGRES_MEM_LIMIT=2g
   MINIO_MEM_LIMIT=1g
   SURICATA_ENABLED=true   # the default; set explicitly if lowered for Minimum

An SSD matters here: Postgres analysis history, MinIO object storage, and nginx
spilling large request bodies to ``/tmp`` are all disk-bound before they are
memory-bound.

.. note::

   **Sizing storage from your own workload.** The figures above are starting
   points. Storage runs to roughly **2.5x the capture volume ingested** — 100 GB
   of captures needs about 250 GB of disk, being the files themselves plus a
   database of comparable size. How much is held at once is set by the retention
   window rather than by how long the tool has been running:

   .. code-block:: text

      steady state  ~=  ingest_per_day  x  2.5  x  (FILE_RETENTION_HOURS / 24)

   If you intend to keep captures indefinitely there is no steady state — size
   for the full corpus. Decide this before installing; see
   :doc:`../operations/production-hardening` (Plan Storage & Retention) and
   :doc:`../operations/scalability`.

.. note::

   The Comfortable tier is an operational recommendation, not a measured
   benchmark. It is derived from the backend guidance in
   :doc:`../operations/production-hardening` (4 GB+ for the backend alone with
   Suricata on captures over 100 MB), with headroom for the rest of the stack.

.. important::

   The default stack declares ~4.4 GB of enforced container memory limits
   (~5.4 GB with an authentication overlay), before the host OS and Docker
   itself — a 4 GB host cannot run it at default settings. See
   :doc:`../operations/production-hardening` for the per-service breakdown and
   the environment variables that override each limit.

   ``.env.example`` ships ``SURICATA_ENABLED=true``, for which 4 GB+ for the
   backend alone is recommended on captures over 100 MB. Budget 8 GB+ if you
   keep Suricata enabled.

.. note::

   TracePcap itself never uses a GPU — packet dissection (tshark, nDPI) and
   threat detection (Suricata) are CPU-bound, and no container in the stack
   requests a GPU device.

   A GPU is relevant only when self-hosting the LLM, and it is that server's
   requirement rather than TracePcap's. Budget roughly 8 GB of VRAM for a 7B
   parameter model or 16 GB for a 14B, quantised, plus 5–30 GB of storage for
   model weights, **on top of** the tiers above. CPU-only inference works but is
   slow enough that long generations such as Story Mode may approach the proxy
   timeout. Pointing ``LLM_API_BASE_URL`` at an LLM server on another machine — which
   still satisfies the offline requirement on a local network — leaves the tiers
   above unchanged.

Operating System
----------------

TracePcap is Docker-based and runs on any OS that supports Docker Compose,
including Linux, macOS, and Windows (via WSL2).
