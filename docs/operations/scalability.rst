Database Scalability
====================

Sizing guidance for PostgreSQL and MinIO as captured data grows. Figures come from an
audit of the live schema, repositories, and infrastructure config.

.. note::

   Growth figures are estimates for typical mixed traffic. Packet density varies widely
   between captures, so treat them as planning shape rather than precise numbers.

Table Growth
------------

Every packet is stored as a row, with the payload capped at **64 bytes**
(``PacketEntity.PAYLOAD_BYTE_LIMIT``, i.e. at most 128 hex characters).

- **~1.5–2M ``packets`` rows per GB of PCAP.**
- A row is roughly 250–400 B, plus four indexes, so **PostgreSQL grows to about
  1–1.5× the PCAP size** — almost entirely ``packets``.
- ``conversations`` holds hundreds to low thousands of rows per GB, but carries
  **14 indexes (5 of them GIN)**, so it is write-amplified despite the small row count.
- ``ip_geo_cache`` and ``host_classifications`` are bounded by the number of distinct
  IPs and hosts. Neither is a scaling concern.

The practical consequence: ``packets`` is the only table whose growth matters, and it is
what any retention or capacity policy should target.

Indexing
--------

**No critical index is missing** for the current per-file query patterns. Two
observations:

- The ``payloadContains`` filter runs ``LIKE '%hex%'`` against ``packets.payload``, which
  is unindexable and results in a sequential scan. It stays file-scoped, so this is
  acceptable at present.
- Aggregation and anomaly queries filter by ``file_id`` and ``GROUP BY`` source or
  destination IP, producing full per-file scans. Also fine at current scale.

Partitioning
------------

Retention deletes whole files, and ``ON DELETE CASCADE`` then removes millions of
``packets`` rows per file on each cleanup cycle, causing significant autovacuum churn.

**List or hash partitioning ``packets`` by ``file_id`` turns cleanup into an instant
``DROP``/``DETACH`` of a partition.** This is the recommended approach and is tracked in
`issue #394 <https://github.com/NotYuSheng/TracePcap/issues/394>`_.

TimescaleDB is a **weaker fit** here. It optimises time-range operations, whereas
TracePcap deletes per file, not per time window.

Connection Pooling
------------------

HikariCP is sized via ``DB_POOL_MAX_SIZE`` (default 20) with ``DB_POOL_MIN_IDLE``
(default 5), set in ``docker-compose.yml`` and inherited by all profiles. This stays well
under the PostgreSQL ``max_connections`` default of 100.

.. note::

   An earlier deployment bug left the pool capped at 10 because the ``dev`` profile did
   not override the datasource and the ``prod`` profile's sizing was never active. Fixed
   in `issue #393 <https://github.com/NotYuSheng/TracePcap/issues/393>`_; the pool is now
   configured in the base compose file so it applies regardless of profile.

Object Storage
--------------

MinIO runs single-node on a ``local`` volume, so capacity is bounded by the host disk and
there is no redundancy. See :doc:`storage-redundancy` for the SPOF discussion and the
SNMD/MNMD upgrade paths.

Archival & Retention
--------------------

A scheduled job prunes analysis files after ``FILE_RETENTION_HOURS`` (default 12h);
retention can be disabled entirely with ``FILE_RETENTION_ENABLED``. **Monitor-mode files
never expire**, which is where unbounded growth actually accumulates.

Pruning is currently all-or-nothing through the file cascade, with no export beforehand.
The recommended policy is to **decouple packet retention from summary retention** — drop
the bulky ``packets`` rows early while keeping ``analysis_results`` and ``conversations``
summaries, since the summaries are a small fraction of the storage. Tracked in
`issue #602 <https://github.com/NotYuSheng/TracePcap/issues/602>`_.

Schema Notes
------------

Corrections against older documentation:

- There is **no ``dns_query_log`` table** in the migrations.
- The geolocation table is **``ip_geo_cache``** (keyed by IP), not ``ip_geo_info``;
  ``IpGeoInfoEntity`` maps to ``ip_geo_cache``.
- Migrations are V1–V15 with V7 absent. ``V1__baseline_schema.sql`` is the source of
  truth for indexes.
