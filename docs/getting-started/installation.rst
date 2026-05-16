Installation
============

This guide walks you through a standard online Docker Compose installation.
For air-gapped environments, see :doc:`offline-deployment`.

1. Clone the Repository
-----------------------

.. code-block:: bash

   git clone https://github.com/NotYuSheng/TracePcap.git
   cd TracePcap

2. Configure Environment Variables
-----------------------------------

Copy the example environment file and edit it:

.. code-block:: bash

   cp .env.example .env

Open ``.env`` in your editor and configure at minimum:

.. code-block:: ini

   # Maximum PCAP upload size (bytes). Default: 512 MB.
   MAX_UPLOAD_SIZE_BYTES=536870912

   # Port on which nginx listens. Change if 80 is already in use.
   NGINX_PORT=80

   # LLM configuration — point to your local inference server.
   LLM_API_BASE_URL=http://localhost:1234/v1
   LLM_API_KEY=
   LLM_MODEL=Qwen2.5-14B-Coder-Instruct
   LLM_TEMPERATURE=0.7
   LLM_MAX_TOKENS=2000

See :doc:`../configuration/environment-variables` for a full reference.

3. Start the Application
------------------------

.. code-block:: bash

   docker compose up -d

On first startup Docker will pull the required images and initialize
PostgreSQL and MinIO. This may take a few minutes.

4. Verify the Stack is Running
-------------------------------

.. code-block:: bash

   docker compose ps

All services — ``tracepcap-backend``, ``tracepcap-frontend``, ``postgres``,
``minio``, and ``nginx`` — should report **healthy** or **running**.

5. Open TracePcap
-----------------

Navigate to ``http://localhost:80`` in your browser (or the port you set in
``NGINX_PORT``).

Next Steps
----------

- Upload a sample PCAP from :doc:`../sample-files` to verify everything works.
- Configure your LLM server — see :doc:`../configuration/llm-setup`.
- Review :doc:`../features/pcap-upload` for upload options and limits.
