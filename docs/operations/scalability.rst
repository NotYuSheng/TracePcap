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

``packets`` is **LIST-partitioned by ``file_id``, one partition per file**
(`issue #394 <https://github.com/NotYuSheng/TracePcap/issues/394>`_). Because retention
deletes whole files, the partition boundary matches the deletion boundary exactly, so
reclaiming a file's frames is a single ``DROP TABLE`` — an O(1) unlink with no row visits,
no index maintenance and nothing left for autovacuum. Previously this was a cascading
delete of millions of rows per file on every cleanup cycle.

Per-file queries benefit too: the planner prunes to the single relevant partition instead
of scanning an index spanning every file.

Two operational consequences:

- A partition is created at ingest, before the first packet insert. There is deliberately
  **no default partition**, so a missing one fails loudly rather than silently landing rows
  somewhere that cannot be dropped instantly.
- Partition count tracks the number of live files. Retention bounds it in normal operation;
  planning cost grows with very large partition counts, so keep retention enabled.

TimescaleDB is a **weaker fit** here. It optimises time-range operations, whereas
TracePcap deletes per file, not per time window.

Splitting packet retention from summary retention
--------------------------------------------------

``packets`` is the bulky table; ``conversations`` and ``analysis_results`` are compact
summaries that stay useful long after the raw frames are worth storing. Setting
``PACKET_RETENTION_HOURS`` below ``FILE_RETENTION_HOURS`` drops the packet partitions early
while the file keeps its summaries, reclaiming most of the storage at the cost of
packet-level drill-down.

Pruned files are stamped with ``files.packets_pruned_at``, which distinguishes "packets
pruned" from "this capture had no packets". Conversation lists, the network graph and all
per-file summaries are unaffected; packet step-through returns an empty list.

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

Capacity Planning
-----------------

Storage consumed is roughly **2.5× the PCAP volume ingested**. Concretely, for
every 100 GB of captures you put in:

.. list-table::
   :header-rows: 1
   :widths: 60 40

   * - What it is
     - Disk needed
   * - The capture files themselves
     - 100 GB
   * - The database they build
     - 100 – 150 GB
   * - **Total**
     - **~250 GB**

Use that multiplier in both directions — to size a disk for a given workload, or
to work out the retention window a given disk can sustain.

Checking where you stand
~~~~~~~~~~~~~~~~~~~~~~~~

``scripts/capacity.sh`` reports current usage and projects forward from the
observed ingest rate:

.. code-block:: bash

   bash scripts/capacity.sh

It is read-only and safe on a live deployment. ``--quiet`` prints a single summary
line, and the exit code makes it usable as a cron canary — ``0`` OK, ``2``
warning, ``3`` critical:

.. code-block:: bash

   0 7 * * * cd /path/to/TracePcap && bash scripts/capacity.sh --quiet || mail -s 'TracePcap capacity' ops@example.com

Thresholds are configurable via ``CAPACITY_WARN_PERCENT`` (default 75),
``CAPACITY_CRIT_PERCENT`` (90), ``CAPACITY_WARN_DAYS`` (30) and
``CAPACITY_RATE_WINDOW_DAYS`` (7).

Sizing a deployment
~~~~~~~~~~~~~~~~~~~

**With retention enabled**, the working set is bounded — you only ever hold one
retention window of captures, so the disk requirement does not grow with time::

   steady state  ~=  ingest_per_day  x  2.5  x  (FILE_RETENTION_HOURS / 24)

For 20 GB of captures a week (~2.9 GB/day) at the default 12-hour retention:
``2.9 × 2.5 × 0.5`` ≈ **3.6 GB** steady state. Retention, not disk size, is what
determines the footprint.

Inverting it gives the retention window a given disk can sustain::

   FILE_RETENTION_HOURS  ~=  (usable_disk x 24) / (ingest_per_day x 2.5)

**With retention disabled** (``FILE_RETENTION_ENABLED=false``), growth is
unbounded and the disk is the only limit::

   days_until_full  ~=  free_disk / (ingest_per_day x 2.5)

The same 2.9 GB/day on a 2 TB disk gives roughly **285 days**. Long-term
retention deployments should plan around that number and revisit it as the
ingest rate changes.

.. important::

   Leave headroom beyond the steady-state figure. ``scripts/backup.sh`` stages an
   uncompressed copy of the data set before archiving, so a backup run needs
   roughly **twice the live data size** free. ``capacity.sh`` checks this and
   reports CRITICAL if the margin is gone.

Two caveats
~~~~~~~~~~~

- **Monitor snapshots are exempt** from ``FILE_RETENTION_HOURS`` and default to
  never expiring, so they are not covered by the steady-state formula. On a
  monitor-heavy deployment they are the component that actually grows without
  bound.
- **Packet density varies widely** between captures. The 2.5× multiplier is a
  planning figure, not a guarantee; ``capacity.sh`` measures your real rate, so
  prefer its output once the deployment has seen representative traffic.

Object Storage
--------------

MinIO runs single-node on a ``local`` volume, so capacity is bounded by the host disk and
there is no redundancy. See :doc:`storage-redundancy` for the SPOF discussion and the
SNMD/MNMD upgrade paths.

Archival & Retention
--------------------

A scheduled job prunes analysis files after ``FILE_RETENTION_HOURS`` (default 12h).
``FILE_RETENTION_ENABLED=false`` keeps everything indefinitely — it is the **master
switch**, and while it is false the scheduler is not registered, so no other retention
setting has any effect.

.. warning::

   ``0`` means "never" only for ``MONITOR_FILE_RETENTION_HOURS`` and
   ``PACKET_RETENTION_HOURS``. For ``FILE_RETENTION_HOURS`` it means *delete everything
   now*. Disable deletion with ``FILE_RETENTION_ENABLED=false``.

Within an enabled scheduler, packet retention is **tunable separately** from file
retention: setting ``PACKET_RETENTION_HOURS`` below ``FILE_RETENTION_HOURS`` drops the
bulky ``packets`` partitions early while keeping the compact ``analysis_results`` and
``conversations`` summaries. See "Splitting packet retention from summary retention"
above.

**Monitor-mode files default to never expiring**
(``MONITOR_FILE_RETENTION_HOURS=0``), because a monitor network is a time series and
expiring its snapshots destroys the drift history. Monitor mode is therefore where
unbounded growth accumulates on a long-lived deployment. Note this pulls against the
partitioning guidance above — retention is what bounds partition count, but monitor
snapshots are exempt from it by default, so a monitor-heavy deployment accrues partitions
that nothing reclaims. Prune those snapshots through the UI rather than by setting a
non-zero value here, until `issue #635
<https://github.com/NotYuSheng/TracePcap/issues/635>`_ is resolved.

See :doc:`../configuration/environment-variables` for all four settings.

Schema Notes
------------

Corrections against older documentation:

- ``dns_query_log`` **does** exist, created by ``V20__dns_query_log.sql``. It did not
  when the original sizing audit was written, and that stale note was carried forward
  here in error.
- The geolocation table is **``ip_geo_cache``** (keyed by IP), not ``ip_geo_info``;
  ``IpGeoInfoEntity`` maps to ``ip_geo_cache``.
- ``V1__baseline_schema.sql`` is the source of truth for the original indexes; later
  migrations amend it (``packets`` partitioning arrived in ``V41``).
