Backup & Restore
================

TracePcap holds three things that cannot be regenerated:

- **PostgreSQL** — analysis results, conversations, monitor snapshots, and every
  human-entered label or override.
- **MinIO** — the raw PCAP objects.
- **config volume** — ``signatures.yml``, your custom detection rules.

``scripts/backup.sh`` captures all three into one timestamped archive, and
``scripts/restore.sh`` puts them back.

.. warning::

   **An untested backup is not a backup.** Rehearse the restore (below) before
   the deployment holds data you care about — while a mistake is still free.

Automated Backups
-----------------

Install the bundled systemd timer for a nightly run at 02:30:

.. code-block:: bash

   sudo cp scripts/tracepcap-backup.service scripts/tracepcap-backup.timer \
     /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable --now tracepcap-backup.timer

Edit ``User``, ``WorkingDirectory`` and ``BACKUP_DIR`` in the ``.service`` file to
match your deployment first. Verify the schedule and check on it with:

.. code-block:: bash

   systemctl list-timers tracepcap-backup.timer
   journalctl -u tracepcap-backup.service -n 50

If you prefer cron:

.. code-block:: bash

   30 2 * * * cd /path/to/TracePcap && bash scripts/backup.sh >> /var/log/tracepcap-backup.log 2>&1

The script exits non-zero on any failure, so both cron and systemd surface a
failed run rather than passing over it silently.

.. important::

   Set ``BACKUP_DIR`` to storage on a **different disk from the deployment** —
   ideally a NAS or mounted remote share. A backup sitting on the same disk as
   the data does not survive that disk failing, which is the main thing it is
   there for.

Configuration
~~~~~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 30 20 50

   * - Variable
     - Default
     - Purpose
   * - ``BACKUP_DIR``
     - ``./backups``
     - Where archives are written. Point at off-host storage.
   * - ``BACKUP_RETENTION_DAYS``
     - ``14``
     - Archives older than this are pruned. ``0`` disables pruning.

Credentials are read from ``.env`` (or the environment), so the script needs no
configuration of its own beyond the two variables above.

Running a Backup Manually
-------------------------

.. code-block:: bash

   bash scripts/backup.sh

   # or to a specific destination
   BACKUP_DIR=/mnt/nas/tracepcap bash scripts/backup.sh

Output is a single archive, ``tracepcap-backup-<timestamp>.tar.gz``, containing
the PostgreSQL dump, the MinIO objects, the config files, and a ``manifest.txt``
recording what was captured.

The script refuses to record a backup as good if the database dump comes back
implausibly small, and verifies the finished archive is readable. **Old backups
are pruned only after the new one passes both checks**, so a failing run can
never destroy your last good archive.

Restoring
---------

.. warning::

   Restoring is **destructive**. It drops and recreates the objects in the target
   database and overwrites objects in the bucket. The script prompts for
   confirmation unless ``FORCE=1`` is set.

Inspect an archive without changing anything:

.. code-block:: bash

   bash scripts/restore.sh --list backups/tracepcap-backup-20260728-110713.tar.gz

Perform the restore, with the backend stopped so nothing writes underneath it:

.. code-block:: bash

   docker compose stop backend
   bash scripts/restore.sh backups/tracepcap-backup-20260728-110713.tar.gz
   docker compose start backend

The script verifies the result rather than trusting exit codes — it counts the
tables actually present afterwards and fails if the database came back empty. It
also rejects corrupt archives and tarballs that are not TracePcap backups.

Rehearsing a Restore
--------------------

Run this on a **non-production** deployment, or before the box holds real data.

1. Upload a PCAP and let it finish analysing.
2. Take a backup: ``bash scripts/backup.sh``
3. Note what you have:

   .. code-block:: bash

      docker exec -e PGPASSWORD=$POSTGRES_PASSWORD tracepcap-postgres \
        psql -U $POSTGRES_USER -d $POSTGRES_DB -tAc \
        "SELECT (SELECT count(*) FROM files), (SELECT count(*) FROM packets)"

4. Simulate the loss — stop the backend, drop the schema, empty the bucket.
5. Restore, restart the backend, and confirm the counts match, the file list
   renders, and a PCAP downloads intact.

This procedure was used to validate the scripts: a full drop of the ``public``
schema and a complete bucket wipe, followed by a restore that returned the exact
row counts and a **byte-identical** PCAP (verified by MD5).

Recovery Objectives
-------------------

.. list-table::
   :header-rows: 1
   :widths: 20 25 55

   * - Objective
     - Value
     - Notes
   * - **RPO**
     - Up to 24 h
     - Set by the nightly schedule. Most lost work is re-importable — PCAPs can
       be re-uploaded and re-analysed — but **human labels and overrides entered
       since the last backup cannot be recovered.**
   * - **RTO**
     - Minutes
     - Dominated by archive size, not by the procedure. Restore is one command.

.. note::

   Backup and restore both complete in about a second on a trivial dataset,
   which tells you the procedure has no fixed overhead — not how long your data
   will take. Time a real backup against your own capture volume and record the
   result. Expect it to track archive size, which is roughly the PCAP volume plus
   a database of comparable size (see :doc:`scalability`).

Reducing the RPO below 24 hours means running the timer more frequently. True
point-in-time recovery would require PostgreSQL WAL archiving, which is
deliberately not configured — a trade for a single-server deployment whose
primary data is re-importable. See `issue #379
<https://github.com/NotYuSheng/TracePcap/issues/379>`_.

What Is Not Covered
-------------------

- **Point-in-time recovery.** Restores land on a nightly boundary, not an
  arbitrary moment.
- **Keycloak users.** The auth overlays persist Keycloak's H2 store in the
  ``keycloak_data`` volume, which these scripts do not capture. Accounts created
  in the admin console must be re-provisioned, or that volume backed up
  separately. The seeded realm import is in version control.
- **Redundancy.** Backups protect against deletion and corruption, not against
  hardware failure taking the service offline. See :doc:`storage-redundancy`.

Manual Procedures
-----------------

The individual commands, if you need to do something the scripts do not cover:

.. code-block:: bash

   # PostgreSQL
   docker exec tracepcap-postgres pg_dump -U tracepcap_user tracepcap > backup.sql
   docker exec -i tracepcap-postgres psql -U tracepcap_user tracepcap < backup.sql

   # MinIO
   docker exec tracepcap-minio mc mirror minio/tracepcap-files ./backup-pcaps/
   docker exec tracepcap-minio mc mirror ./backup-pcaps/ minio/tracepcap-files

   # Signature rules
   docker cp tracepcap-backend:/app/config/signatures.yml ./signatures.yml.bak

Export Options
--------------

From within the UI, you can also export data without accessing Docker directly:

- **PDF report** — click **Export PDF** on any PCAP overview page. The report
  includes a live capture of the network topology.
- **CSV** — export the current Conversations view to a spreadsheet.
- **PCAP** — download individual or bulk conversation PCAPs from the
  Conversations tab.
