Storage Redundancy & Capacity
==============================

This page documents a **known limitation**, not a configuration step. TracePcap's
object store is currently a single point of failure. Nothing here is enabled by
default, and closing the gap requires additional hardware.

Current Deployment
------------------

TracePcap runs MinIO in **Single-Node Single-Drive (SNSD)** mode — ``server /data``
backed by one ``local`` Docker volume in ``docker-compose.yml``:

- **No erasure coding and no redundancy.** A drive failure loses every stored PCAP.
- **Capacity is bounded by the host disk.** There is no way to grow past it without
  adding storage to the machine.

Database growth compounds this. Per the datastore sizing work, PostgreSQL grows to
roughly **1–1.5× the size of the ingested PCAP** (see :doc:`../operations/scalability`),
so the host disk carries both the raw objects and a database of comparable size.

Redundancy Options
------------------

In increasing order of cost and resilience:

**SNMD — Single-Node Multi-Drive**
   Same machine, MinIO given **four or more drives/volumes**. Erasure coding then
   tolerates a **drive** failure. Requires no additional machines.

**MNMD — Multi-Node Multi-Drive**
   **Four or more nodes**, giving true high availability that tolerates the loss of a
   whole **machine**. Only necessary if a full-host outage must be survived.

Recommendation
--------------

For a single-server deployment, **SNMD is the first redundancy step** — it removes the
drive-failure SPOF without any multi-machine work, and needs no application change.
MNMD is a Stage 2 concern and should be considered alongside the wider high-availability
and scale-out work.

In the meantime:

- Document the SPOF for whoever operates the box.
- Alert on host disk usage, since capacity is bounded by it and both MinIO and
  PostgreSQL consume it.

.. note::

   **Redundancy is not backup.** Erasure coding protects against hardware failure; it
   does not protect against accidental deletion, corruption, or operator error. Both
   are needed. Backup and restore procedures are covered in :doc:`backup-restore`, and
   automating them is tracked separately in `issue #379
   <https://github.com/NotYuSheng/TracePcap/issues/379>`_.
