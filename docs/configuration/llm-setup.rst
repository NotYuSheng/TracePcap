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

Changing It Without a Restart
-----------------------------

The ``.env`` values are the starting point. The server, key, model, temperature,
max tokens, timeout and tool calling can also be changed in **Settings › System ›
LLM**, by whoever has the *Edit the LLM connection* permission (admins by default;
with login off, that needs ``SYSTEM_SETTINGS_EDITABLE=true``). A change applies to
the next LLM call: the client re-checks the new server's limits and, with tool
calling on ``auto``, asks it afresh whether it supports tools. The API key is
never shown again once saved, and the audit log records only that it changed.
**Reset to the deployment's value** goes back to ``.env``.

Testing the Connection
-----------------------

**Settings › System › LLM › Test connection** checks the connection in four steps,
and says which one fails:

1. **Reach the server**: ``LLM_API_BASE_URL/models`` answers, and how fast.
2. **Key accepted**: the server doesn't refuse the key (401 or 403).
3. **Model available**: the model is among the server's models. The server's models
   are listed, and clicking one makes it the model.
4. **Model replies**: a one-token chat completion comes back.

Anyone can test what's in effect. When changing the URL, key or model, **Test this
value** tests the typed value before saving it (that needs the permission, since it
sends requests to the typed address). If a step fails, check:

1. The inference server is running.
2. ``LLM_API_BASE_URL`` is correct and reachable from inside the Docker
   network (use the host's LAN IP, not ``localhost``, if the LLM runs on the
   same machine but outside Docker).
3. The model name in ``LLM_MODEL`` matches a loaded model on the server.

.. note::

   If TracePcap runs in Docker and the LLM server runs on the host machine,
   use ``http://host.docker.internal:1234/v1`` (Docker Desktop) or the host's
   LAN IP address instead of ``localhost``.
