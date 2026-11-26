LLM Setup
=========

TracePcap's AI features (Story Mode and its chat, which also writes filters) require an
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

**Change connection…** opens the URL, key and model as one form. Once a URL is
typed (and a key, if it needs one), the server is asked for its models and the
model becomes a dropdown of them, with each one's context length when the server
says. A server that doesn't list its models leaves the model to be typed. Test the
values there, then **Save**: each changed setting is saved and audited on its own.

Testing the Connection
-----------------------

**Settings › System › LLM › Test connection** checks the connection step by step,
and says which one fails, or warns:

1. **Reach the server**: ``LLM_API_BASE_URL/models`` answers, and how fast.
2. **Key accepted**: the server doesn't refuse the key (401 or 403).
3. **Model available**: the model is among the server's models, and can chat. The
   server's models are listed, and clicking one makes it the model.
4. **Model replies**: a short chat completion comes back, from that model.
5. **Takes tools** (when the server says): whether the chat can look things up.
6. **Can carry a story**: from the model's context, the reply's speed and
   ``LLM_MAX_TOKENS``. It warns, without failing, when:

   * the context is under 16,384 tokens (a story on a busy capture sends
     10,000–20,000), or under 32,768 for a reasoning model, which thinks first;
   * ``LLM_MAX_TOKENS`` caps replies under 4,000 (24,000 for a reasoning model);
   * at the speed it replied, a story (about 4,000 tokens, three times that for
     a reasoning model) would run past ``LLM_TIMEOUT``. The test reply's time
     includes reading the prompt, so the speed is a floor.

   Otherwise it says the context and how long a story takes.

Anyone can test what's in effect. When changing the URL, key or model, **Test these
values** tests the typed values before saving them (that needs the permission, since it
sends requests to the typed address). If a step fails, check:

1. The inference server is running.
2. ``LLM_API_BASE_URL`` is correct and reachable from inside the Docker
   network (use the host's LAN IP, not ``localhost``, if the LLM runs on the
   same machine but outside Docker).
3. The model name in ``LLM_MODEL`` matches a loaded model on the server.

Model Types
-----------

TracePcap needs a model that chats. What it does with the other kinds:

.. list-table::
   :header-rows: 1
   :widths: 25 75

   * - Model
     - What happens
   * - **Chat** (instruct)
     - Works. Story, the chat and its tools.
   * - **Vision** (VLM)
     - Works; it chats too. The test says it's a vision model.
   * - **Reasoning** (thinks before it answers: DeepSeek-R1, Qwen3 thinking, …)
     - Works. Its thinking is dropped before the answer is read, whether the server sends
       it apart or inline as ``<think>…</think>``. The test says it's a reasoning model:
       leave ``LLM_MAX_TOKENS`` at ``0`` (each reply gets what the context has left) or
       give it 24000 or more, and a long ``LLM_TIMEOUT``, or it can spend the whole reply
       thinking. If it does, the error says so and what to raise.
   * - **Embedding** (``text-embedding-…``, ``bge-…``)
     - Refused, with a clear message: it turns text into numbers for search and can't
       write answers. The test stops at *Model available*; Story and the chat fail at
       once, before calling the server.
   * - **No tool support**
     - Works; the chat answers from the findings and the story, and says it answered
       without tools. Servers that say which models take tools (LM Studio) let TracePcap
       skip offering them; others are found out on the first question.

TracePcap learns a model's kind from LM Studio's ``/api/v0/models`` when the server is
LM Studio, and otherwise from its name.

**Another model answering.** Some servers answer with whatever model they have loaded,
whatever name the request gives. The test then warns *Replied, but as …*, the chat notes
*Answered by …, not …* under the answer, and a story records the model that actually
wrote it. Load the configured model on the server, or set the model to the loaded one.

.. note::

   If TracePcap runs in Docker and the LLM server runs on the host machine,
   use ``http://host.docker.internal:1234/v1`` (Docker Desktop) or the host's
   LAN IP address instead of ``localhost``.
