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

**Minimum:**

- RAM: 4 GB
- Storage: 10 GB (database, PCAP files, object storage)

**Recommended:**

- RAM: 8 GB or more
- Storage: 50 GB+ for large PCAP collections
- CPU: 4+ cores for fast nDPI analysis

.. note::

   If you plan to run an LLM locally for AI features, allocate additional RAM
   (8–16 GB typical for a 7B–14B parameter model).

Operating System
----------------

TracePcap is Docker-based and runs on any OS that supports Docker Compose,
including Linux, macOS, and Windows (via WSL2).
