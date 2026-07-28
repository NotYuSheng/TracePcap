Security Audit
==============

A readiness-oriented review of the application and deployment surface.

.. warning::

   This is a **lightweight readiness pass over public source**, not a certified
   penetration test or a formal security audit. It is intended to prioritise hardening
   work, not to certify the application as secure.

Context
-------

TracePcap was originally designed for small, single-user sessions — an analyst uploading
a capture and reviewing results locally. The open defaults and absence of authentication
reflect that original scope. The findings below matter as the project moves toward
persistent, multi-user deployments.

Findings
--------

**1. Unauthenticated signature management**

``SignaturesController`` exposes ``GET`` and ``PUT`` of raw YAML signature content and
writes to ``tracepcap.signatures.path``. Even with SnakeYAML's ``SafeConstructor`` in
place, these endpoints should require authentication and authorisation, and should be
audit-logged.

**2. Download filename handling**

``FileController.download`` builds ``Content-Disposition`` from the stored original
filename directly (``attachment; filename=" + fileName``). This should use RFC 6266-safe
encoding and sanitisation to avoid malformed headers or unsafe client behaviour.

**3. Deployment defaults expose sensitive services**

``docker-compose.yml`` ships default PostgreSQL and MinIO credentials, exposes PostgreSQL
on ``5432`` and MinIO on ``9000``/``9001``, and configures the bucket as anonymous public.
These are appropriate for local development and **risky for anything else**. Credential
rotation is tracked in `#595 <https://github.com/NotYuSheng/TracePcap/issues/595>`_; the
intent is also to stop exposing PostgreSQL and MinIO ports externally, since nothing
outside the Docker network needs to reach them.

**4. Broad CORS with credentials**

``WebConfig`` and ``application.yml`` combine environment-supplied origins with
``allowed-headers: "*"`` and ``allow-credentials: true``. Production deployments must set
explicit trusted origins and avoid broad CORS while credentials are enabled. The ``prod``
profile requires ``CORS_ALLOWED_ORIGINS`` to be set.

**5. Sort parameter validation**

``FileController.getAllFiles`` accepts a ``sort`` parameter and passes the requested
property into ``Sort.by``. Sortable fields should be allowlisted to avoid unexpected
property references and backend errors.

Positive Findings
-----------------

- Upload storage uses **UUID-based object names** and validates extension and size.
- PCAP merging uses ``ProcessBuilder`` **argument lists** (not shell strings), together
  with temp files, filename sanitisation, and a timeout.
- ``JdbcTemplate`` queries in ``NodeRoleService`` use **parameterised placeholders** for
  ``fileId`` and ``entityKey``.

Deployment Requirements
-----------------------

Any deployment beyond local development must:

- Override **all** sample credentials — PostgreSQL, MinIO, and the Keycloak admin
  (`#595 <https://github.com/NotYuSheng/TracePcap/issues/595>`_).
- Restrict exposed services so PostgreSQL and MinIO are not externally reachable.
- Terminate **TLS** at nginx (see :doc:`production-hardening`).
- Set explicit ``CORS_ALLOWED_ORIGINS``.
- Point the LLM at a **local inference server**, so capture-derived content is never sent
  to a third party.
- Enable authentication via the Keycloak overlay where the deployment is shared
  (see :doc:`../configuration/authentication`).

Outstanding Work
----------------

Items 1, 2, 4, and 5 above remain open and are tracked in
`#364 <https://github.com/NotYuSheng/TracePcap/issues/364>`_. Multi-user data isolation —
file ownership and provenance, needed before mutually untrusted users share an instance —
is tracked separately in
`#361 <https://github.com/NotYuSheng/TracePcap/issues/361>`_.

.. note::

   The initial public-source review was contributed by `@bmtriet
   <https://github.com/bmtriet>`_ in
   `#364 <https://github.com/NotYuSheng/TracePcap/issues/364>`_.
