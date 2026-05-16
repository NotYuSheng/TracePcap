Backup & Restore
================

TracePcap data lives in two places:

- **PostgreSQL** — conversation metadata, analysis results, geolocation data.
- **MinIO** — raw PCAP files (object storage).

Backing Up
----------

Database Backup
~~~~~~~~~~~~~~~

.. code-block:: bash

   docker exec tracepcap-postgres \
     pg_dump -U tracepcap_user tracepcap > backup.sql

MinIO Backup (PCAP files)
~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: bash

   docker exec tracepcap-minio \
     mc mirror minio/tracepcap-files ./backup-pcaps/

Full Volume Backup
~~~~~~~~~~~~~~~~~~

To back up all Docker named volumes at once:

.. code-block:: bash

   sudo tar -czf tracepcap_backup.tar.gz /var/lib/docker/volumes/tracepcap_*

Custom Signature Rules Backup
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The rules file is stored in the ``config_data`` volume. Back it up with:

.. code-block:: bash

   docker cp tracepcap-backend:/app/config/signatures.yml ./signatures.yml.bak

Restoring
---------

Database Restore
~~~~~~~~~~~~~~~~

.. code-block:: bash

   docker exec -i tracepcap-postgres \
     psql -U tracepcap_user tracepcap < backup.sql

MinIO Restore
~~~~~~~~~~~~~

.. code-block:: bash

   docker exec tracepcap-minio \
     mc mirror ./backup-pcaps/ minio/tracepcap-files

Export Options
--------------

From within the UI, you can also export data without accessing Docker directly:

- **PDF report** — click **Export PDF** on any PCAP overview page. The report
  includes a live capture of the network topology.
- **CSV** — export the current Conversations view to a spreadsheet.
- **PCAP** — download individual or bulk conversation PCAPs from the
  Conversations tab.
