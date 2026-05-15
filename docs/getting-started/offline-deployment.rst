Offline / Air-Gapped Deployment
================================

TracePcap is designed to run fully offline — no external API calls are made
at runtime. This page covers the workflow for deploying to a machine that has
no internet access.

Overview
--------

1. On an **internet-connected** machine: pull all images and save them as
   ``.tar`` files.
2. **Transfer** the tarballs (plus a few scripts) to the offline machine.
3. On the **offline machine**: load the images and start the stack.

Step 1 — Pull and Save Images (online machine)
----------------------------------------------

.. code-block:: bash

   bash scripts/pull-and-save-images.sh

This creates an ``images/`` directory containing ``.tar`` files for every
service (backend, frontend, postgres, minio, nginx, …).

Step 2 — Transfer Files to the Offline Machine
-----------------------------------------------

Copy the following to the offline machine (USB drive, SCP, etc.):

.. code-block:: text

   images/                        # all .tar image archives
   docker-compose.offline.yml
   scripts/load-images.sh
   .env                           # copy from .env.example and configure first

Step 3 — Load Images and Start the Stack (offline machine)
----------------------------------------------------------

.. code-block:: bash

   # Load all images into Docker
   bash scripts/load-images.sh

   # Start the stack using the offline compose file
   docker compose -f docker-compose.offline.yml up -d

LLM Configuration for Offline Use
----------------------------------

AI features (Story Mode, AI Filter Generator) require an OpenAI-compatible
inference server. The offline compose file defaults to:

.. code-block:: ini

   LLM_API_BASE_URL=http://localhost:1234/v1

Configure a locally-hosted LLM (e.g. `LM Studio <https://lmstudio.ai>`_ or
`Ollama <https://ollama.com>`_) and set ``LLM_API_BASE_URL`` in your ``.env``
before starting. See :doc:`../configuration/llm-setup` for details.

.. note::

   If no LLM server is available, TracePcap works fully without AI features —
   only Story Mode and AI Filter Generator will be non-functional.
