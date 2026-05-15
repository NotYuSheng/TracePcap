AI Filter Generator
===================

The AI Filter Generator converts a **natural language query** into a ready-to-use
**Wireshark display filter** or **tcpdump capture filter** using a locally-hosted
LLM.

Requirements
------------

A configured LLM server is required (see :doc:`../configuration/llm-setup`).
The feature gracefully degrades — if the LLM is unavailable, the input box is
disabled and a warning is shown.

How to Use
----------

1. Open the **AI Filter** tab for a PCAP.
2. Type your query in plain English, for example:

   - *"Show all TLS traffic to external IPs"*
   - *"Find DNS requests from 192.168.1.5"*
   - *"Filter out ICMP and show only TCP on port 443"*

3. Click **Generate**.
4. The LLM returns:

   - A **Wireshark display filter** (e.g. ``tls && !ip.dst == 10.0.0.0/8``).
   - A **tcpdump capture filter** (e.g. ``port 443 and not net 10.0.0.0/8``).
   - A **confidence score** (0–100%).
   - A brief **explanation** of the filter logic.

5. TracePcap immediately applies the generated filter against the PCAP data
   and shows the **matching packet count** in the results panel below.

Confidence Score
----------------

The confidence score reflects the LLM's self-assessed certainty that the
generated filter correctly captures the intent of your query. Scores below
~60% typically indicate ambiguous queries — consider refining your wording.

Privacy
-------

Filter queries are sent to whatever ``LLM_API_BASE_URL`` you have configured.
To keep queries private, use a local inference server (LM Studio, Ollama).
No query data is sent to Anthropic or any third-party by TracePcap itself.
