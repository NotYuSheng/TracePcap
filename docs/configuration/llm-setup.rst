LLM Setup
=========

TracePcap's AI features (Story Mode and AI Filter Generator) require an
OpenAI-compatible inference server. Any server that implements the
``/v1/chat/completions`` endpoint works.

Supported Servers
-----------------

**LM Studio** (recommended for offline use)

1. Download and install `LM Studio <https://lmstudio.ai>`_.
2. Download a model (e.g. ``Qwen2.5-14B-Coder-Instruct``).
3. Start the local server on port ``1234`` (default).
4. In ``.env``:

   .. code-block:: ini

      LLM_API_BASE_URL=http://localhost:1234/v1
      LLM_API_KEY=
      LLM_MODEL=Qwen2.5-14B-Coder-Instruct

**Ollama**

1. Install `Ollama <https://ollama.com>`_.
2. Pull a model: ``ollama pull qwen2.5-coder:14b``
3. Ollama serves on port ``11434`` by default.
4. In ``.env``:

   .. code-block:: ini

      LLM_API_BASE_URL=http://localhost:11434/v1
      LLM_API_KEY=ollama
      LLM_MODEL=qwen2.5-coder:14b

**OpenAI API** *(not suitable for offline deployments)*

.. code-block:: ini

   LLM_API_BASE_URL=https://api.openai.com/v1
   LLM_API_KEY=sk-...
   LLM_MODEL=gpt-4o

Model Recommendations
---------------------

For best results with filter generation and narrative analysis, use a model
with strong instruction-following and code understanding:

- **Qwen2.5-14B-Coder-Instruct** — good balance of quality and speed on CPU.
- **Qwen2.5-7B-Coder-Instruct** — lighter option for machines with less RAM.
- **Llama-3.1-8B-Instruct** — general-purpose alternative.

Testing the Connection
-----------------------

After configuring ``.env`` and restarting the stack, open the **AI Filter**
tab. If the LLM server is reachable, the text input will be enabled. If it
shows a warning, check:

1. The inference server is running.
2. ``LLM_API_BASE_URL`` is correct and reachable from inside the Docker
   network (use the host's LAN IP, not ``localhost``, if the LLM runs on the
   same machine but outside Docker).
3. The model name in ``LLM_MODEL`` matches a loaded model on the server.

.. note::

   If TracePcap runs in Docker and the LLM server runs on the host machine,
   use ``http://host.docker.internal:1234/v1`` (Docker Desktop) or the host's
   LAN IP address instead of ``localhost``.
