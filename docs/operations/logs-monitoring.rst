Logs & Monitoring
=================

Viewing Logs
------------

All services log to stdout/stderr, captured by Docker Compose.

**All services:**

.. code-block:: bash

   docker compose logs -f

**Specific services:**

.. code-block:: bash

   docker compose logs -f tracepcap-backend
   docker compose logs -f tracepcap-frontend
   docker compose logs -f postgres
   docker compose logs -f minio
   docker compose logs -f nginx

Log Levels
----------

The backend uses Spring Boot logging. To increase verbosity, add to your
``docker-compose.yml`` or ``.env``:

.. code-block:: yaml

   environment:
     LOGGING_LEVEL_ROOT: DEBUG

For production, keep the default ``INFO`` level to avoid excessive log volume.

Health Checks
-------------

Each service in ``docker-compose.yml`` defines a Docker health check. You can
inspect health status with:

.. code-block:: bash

   docker compose ps

A service in ``unhealthy`` state indicates a startup failure or runtime error.
Check its logs first:

.. code-block:: bash

   docker compose logs tracepcap-backend --tail=100

Restarting Services
-------------------

.. code-block:: bash

   # Restart all services
   docker compose restart

   # Restart a specific service
   docker compose restart tracepcap-backend

Monitoring Disk Usage
---------------------

PCAP files can be large. Monitor MinIO storage with:

.. code-block:: bash

   docker exec tracepcap-minio mc du minio/tracepcap-files

And PostgreSQL database size:

.. code-block:: bash

   docker exec tracepcap-postgres \
     psql -U tracepcap_user tracepcap -c "\l+"
