Kubernetes (Helm)
=================

TracePcap has a Helm chart, maintained in its own repository:
`NotYuSheng/tracepcap-helm <https://github.com/NotYuSheng/tracepcap-helm>`_. It deploys the
same stack as the Compose files (nginx frontend, Spring Boot backend, PostgreSQL, MinIO), and
it can run air-gapped too.

.. note::

   The chart needs TracePcap images from a release **after v0.4.0**. Earlier nginx images
   proxy to a Docker-only DNS server, so ``/api`` returns 502 on a cluster. Earlier releases
   also published no version-tagged images for the chart to pin.

Install
-------

.. code-block:: bash

   helm install tracepcap oci://ghcr.io/notyusheng/charts/tracepcap \
     --namespace tracepcap --create-namespace \
     --set backend.llm.baseUrl=http://<inference-host>:1234/v1

   kubectl -n tracepcap rollout status deploy/tracepcap-backend
   kubectl -n tracepcap port-forward svc/tracepcap-frontend 8080:80   # http://localhost:8080
   helm test tracepcap -n tracepcap

To expose it, set ``ingress.enabled=true`` and a host. The chart presets the ingress-nginx
annotations that large uploads and long analysis requests need (no body-size cap, a 960 s
proxy timeout, unbuffered request bodies).

How it maps to the Compose stack
--------------------------------

.. list-table::
   :header-rows: 1
   :widths: 25 75

   * - Compose
     - Chart
   * - ``nginx`` service
     - ``frontend`` Deployment. Stateless, so ``frontend.replicaCount`` can exceed 1. The chart
       sets ``NGINX_BACKEND_URL`` to the backend's fully qualified Service name (see
       :doc:`../configuration/environment-variables`).
   * - ``backend`` service
     - ``backend`` Deployment. Always **one replica** with the ``Recreate`` strategy, because
       analysis and the AI job queue run in-process. An init container waits for the
       datastores, as ``depends_on: service_healthy`` does in Compose.
   * - ``APP_MEMORY_MB`` / ``BACKEND_MEM_LIMIT``
     - ``backend.memoryMB`` and ``backend.resources.limits.memory``. Keep them equal; the
       entrypoint sizes the heap, upload cap and timeouts from the enforced limit.
   * - ``postgres`` / ``minio`` services
     - Bundled single-instance StatefulSets, or ``postgresql.enabled=false`` with
       ``externalDatabase.*`` and ``minio.enabled=false`` with ``externalS3.*``.
   * - ``minio-init`` (bucket) and ``minio-volume-perms`` (chown)
     - Not needed: the backend creates its bucket on startup, and ``fsGroup`` gives MinIO its
       volume.
   * - Other backend variables
     - ``backend.extraEnv`` (``NAME: value``), applied last.

Air-gapped clusters
-------------------

Mirror these images into your registry, keeping their repository paths:
``notyusheng/tracepcap-backend``, ``notyusheng/tracepcap-nginx``,
``library/postgres:15-alpine``, ``chainguard/minio:latest`` and ``library/busybox:1.37``.
Download the chart ``.tgz`` from the chart repository's GitHub releases, then install with
``--set global.imageRegistry=<your-registry>``. ``backend.geoForceOffline`` defaults to
``true``, so the backend makes no ipinfo.io calls (see :doc:`offline-deployment`).

Limitations
-----------

- **Login is not wired up.** Auth is compiled into the frontend image at build time (see
  :doc:`../configuration/authentication`), and no auth-enabled image is published.
- **Pod Security:** the backend entrypoint starts as root and drops to an unprivileged user
  with ``gosu``. It meets the ``baseline`` Pod Security Standard but not ``restricted``.

Every chart value is documented in the chart repository's ``values.yaml``.
