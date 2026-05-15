Story Mode
==========

Story Mode uses an LLM to produce a human-readable **narrative reconstruction**
of the network activity captured in a PCAP file, along with an interactive
Q&A chat.

Requirements
------------

A configured LLM server is required (see :doc:`../configuration/llm-setup`).

What Story Mode Produces
------------------------

Narrative Summary
~~~~~~~~~~~~~~~~~

The LLM analyses conversation metadata (IPs, ports, protocols, applications,
risk flags, timestamps, geolocation, custom signature matches) and generates
a structured narrative that describes:

- Who was communicating with whom.
- What applications and protocols were used.
- When notable events occurred.
- Any detected anomalies or risk indicators.
- A timeline of significant events.

Story Timeline
~~~~~~~~~~~~~~

Below the narrative, a visual **timeline** marks the key events extracted from
the story (e.g. "DNS lookup for evil.com", "TLS session established",
"File download detected") in chronological order.

Interactive LLM Q&A Chat
~~~~~~~~~~~~~~~~~~~~~~~~~

After the narrative is generated, a chat panel allows you to ask follow-up
questions about the PCAP, for example:

- *"Which IP downloaded the most data?"*
- *"Were there any connections to known threat IPs?"*
- *"Summarise the DNS activity."*

The LLM answers using the PCAP metadata as context.

Custom Context
~~~~~~~~~~~~~~

You can provide additional context before generating the story — for example,
a description of the network environment or the timeframe of an incident.
This helps the LLM produce a more accurate and relevant narrative.

Privacy
-------

Story generation sends conversation metadata (not raw packet payloads) to your
configured ``LLM_API_BASE_URL``. Use a local LLM to keep this data fully
within your infrastructure.
