Production Readiness
====================

An assessment of what TracePcap needs before operational use, and where that work
currently stands.

.. note::

   **Two scopes exist.** The original assessment targeted a Kubernetes/Helm deployment
   and estimated 6.5–9 weeks across three phases. A later leadership review narrowed the
   near-term goal to a **single server serving roughly 10–25 analysts**, staged as:

   - **Stage 1 — "safely run what we have"** (~15–20 days): handle large imports, support
     concurrent use, and protect against data loss, on one box.
   - **Stage 2 — "build a team workspace"** (multi-month): per-user logins and RBAC,
     high availability, scale-out, and K8s packaging.

   **Stage 1 is the current target.** The Kubernetes findings below remain valid but are
   Stage 2 work.

Stage 1 Checklist
-----------------

.. list-table::
   :header-rows: 1
   :widths: 40 15 45

   * - Item
     - Status
     - Notes
   * - Concurrent multi-user use
     - Done
     - Reads are not the constraint; ingestion is. See `#453 <https://github.com/NotYuSheng/TracePcap/issues/453>`_.
   * - Load test + tuning
     - Done
     - k6 sweep, 5→30 concurrent uploads. See `#453 <https://github.com/NotYuSheng/TracePcap/issues/453>`_.
   * - Production settings active
     - Done
     - ``prod`` profile in the auth overlays (`#376 <https://github.com/NotYuSheng/TracePcap/issues/376>`_).
   * - Crash / memory safety
     - Done
     - Resource limits on all services (`#378 <https://github.com/NotYuSheng/TracePcap/issues/378>`_).
   * - Indexing & query tuning
     - Done
     - No critical index gaps found. See :doc:`scalability`.
   * - Retention & capacity planning
     - Partial
     - Cleanup exists; partitioning (`#394 <https://github.com/NotYuSheng/TracePcap/issues/394>`_) and retention decoupling (`#602 <https://github.com/NotYuSheng/TracePcap/issues/602>`_) open.
   * - Automated backups + tested restore
     - **Open**
     - Manual procedures only (`#379 <https://github.com/NotYuSheng/TracePcap/issues/379>`_).
   * - Default credential rotation
     - **Open**
     - Shipped defaults still present (`#595 <https://github.com/NotYuSheng/TracePcap/issues/595>`_).
   * - UAT before go-live
     - **Open**
     - `#596 <https://github.com/NotYuSheng/TracePcap/issues/596>`_.

Backups are the critical path: they are the largest remaining item, and UAT is gated on
having rehearsed a restore.

Findings
--------

Findings from the original assessment, by priority. Several are now closed; the priority
labels reflect the original K8s-targeted assessment.

**P0 — blocking**

- **P0-1 No authentication.** Addressed by the optional OIDC/Keycloak overlay
  (`#360 <https://github.com/NotYuSheng/TracePcap/issues/360>`_). The base stack remains
  deliberately open for local use. Multi-user data ownership is separate
  (`#361 <https://github.com/NotYuSheng/TracePcap/issues/361>`_).
- **P0-2 Public MinIO bucket.** See :doc:`security-audit`.
- **P0-3 Dev profile active in the production path.** Fixed
  (`#376 <https://github.com/NotYuSheng/TracePcap/issues/376>`_).
- **P0-4 Default credentials.** Still open
  (`#595 <https://github.com/NotYuSheng/TracePcap/issues/595>`_).

**P1 — required for production**

- **P1-1/2/6 Observability.** Prometheus metrics, health probes, and log aggregation
  (`#377 <https://github.com/NotYuSheng/TracePcap/issues/377>`_,
  `#483 <https://github.com/NotYuSheng/TracePcap/issues/483>`_).
- **P1-3 No resource limits / OOM risk.** Fixed
  (`#378 <https://github.com/NotYuSheng/TracePcap/issues/378>`_).
- **P1-4 No TLS.** Terminate at nginx; see :doc:`production-hardening`.
- **P1-5 No automated backups or PITR.**
  (`#379 <https://github.com/NotYuSheng/TracePcap/issues/379>`_).
- **P1-7 Secrets management.** Stage 1 covers credential rotation
  (`#595 <https://github.com/NotYuSheng/TracePcap/issues/595>`_); a secrets manager is
  Stage 2.

**P2 — scale-out**

- **P2-1 In-process analysis cannot scale out.** Queue-backed stateless workers
  (`#380 <https://github.com/NotYuSheng/TracePcap/issues/380>`_).
- **P2-2 Scheduled cleanup double-runs** across instances
  (`#381 <https://github.com/NotYuSheng/TracePcap/issues/381>`_).
- **P2-3 Datastore SPOFs and scaling.** See :doc:`scalability` and
  :doc:`storage-redundancy`.
- **P2-4 Runtime ipinfo.io egress.** Closed by the ``GEO_FORCE_OFFLINE`` flag
  (`#382 <https://github.com/NotYuSheng/TracePcap/issues/382>`_).
- **P2-5/6 Migration hygiene and K8s/Helm packaging**
  (`#383 <https://github.com/NotYuSheng/TracePcap/issues/383>`_).

Capacity
--------

From the k6 load testing (`#453 <https://github.com/NotYuSheng/TracePcap/issues/453>`_):

- **Concurrent analysts browsing results are not the constraint.** Read endpoints are
  sub-second and comfortably handle 10+ users on modest hardware.
- **Ingestion throughput is the real limit.** The pipeline is CPU-bound and dominated by
  Suricata, which accounts for roughly **94% of per-file analysis time**
  (`#569 <https://github.com/NotYuSheng/TracePcap/issues/569>`_).
- The breaking point measured was **~20 simultaneous analyses** before latency exceeded a
  four-minute budget. This scales with core count rather than being a fixed ceiling.
- Failure mode is **graceful degradation through queueing**, not errors — until the queue
  overflows (fixed in `#451 <https://github.com/NotYuSheng/TracePcap/issues/451>`_).

.. warning::

   Those figures came from a shared, contended development box using a small 538 KB
   capture. They indicate relative cost and shape, **not absolute capacity** on
   production hardware.

Offline Operation
-----------------

The offline requirement holds end to end. GeoIP falls back to a bundled DB-IP Lite MMDB
and can be forced offline with ``GEO_FORCE_OFFLINE``; maps use bundled SVG/GeoJSON with no
tile servers; and the LLM is configured against a local inference server. Image bundling
for air-gapped installs is covered in :doc:`../getting-started/offline-deployment`.
