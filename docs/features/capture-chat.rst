Ask About a Capture (Chat and Tools)
====================================

On a capture's **Story** tab, **Ask about this capture** answers questions in plain English. The
LLM looks things up with **tools** before it answers, and every answer shows the tools it used.
It also writes Wireshark display filters, checked against the capture, which is what the old
Filter Generator tab did.

The chat needs a configured LLM (see :doc:`../configuration/llm-setup`). It works as soon as a
capture is analysed; a written story (see :doc:`story-mode`) gives it more to go on.

Asking
------

Type a question and press **Enter**. Examples:

- *What's critical in this capture?*
- *What is 192.168.110.9, and who does it talk to?*
- *Which device had 10.20.20.51 at 17:25?*
- *A filter for the beacon traffic.*

While it works, the answer shows each tool as it runs (*Looking things up…*). When it is done,
**Used 3 tools · 6 s** above the answer opens the list: each tool, what it was asked, and a line on
what came back. Suggested follow-up questions appear as chips above the question box.

A filter comes back as a card, already checked against this capture: **Valid · 50 packets match**,
**Copy**, and **Show packets**, which opens the matching packets in a side drawer.

The Tools
---------

**Tools · 8** in the chat's header lists them. All are read-only, and all work only on the capture
you are looking at: the capture is fixed by the server, never chosen by the model.

.. list-table::
   :header-rows: 1
   :widths: 25 75

   * - Tool
     - What it looks up
   * - **Findings**
     - The capture's deterministic findings (beacons, fan-out, long sessions, risk flags), by
       severity, type or host.
   * - **Conversations**
     - Flows by host, port, protocol, application or nDPI flag, busiest first.
   * - **Traffic over time**
     - Packets and bytes over the capture, for all of it or one host.
   * - **Host**
     - One address: name, device type, MAC and vendor, roles, its network, whether other devices
       held it, and its traffic (top peers and applications).
   * - **Who held an address**
     - Which device held an IP over the capture, and at a given time (from ARP and DHCP), and
       devices that moved address.
   * - **DNS lookups**
     - Names looked up through each DNS server, with the answers. The log is per server, so it
       says what was looked up and the answer, not which client asked.
   * - **Where traffic goes**
     - Traffic by organisation or country.
   * - **Check a filter**
     - Whether a Wireshark display filter is valid on this capture, and how many packets match.

How It Works
------------

1. The question goes to the LLM with the capture's confirmed findings (and the story, if written)
   and the list of tools.
2. The LLM either answers or asks for tools. TracePcap runs them on the capture and sends the
   results back; this repeats up to six rounds (twelve tool calls), then the LLM must answer.
3. Tool output is marked as data read from the capture. A capture can carry text an attacker
   chose (DNS names, user agents, payloads), and the model is told never to follow it.

The answer arrives in the background and the page checks on it every second, which is how each
tool step shows as it happens.

**When the LLM doesn't take tools.** ``LLM_TOOL_CALLING`` (*auto* by default, see
:doc:`settings`) decides. On *auto*, the first question tries tools; if the LLM server rejects
them, the chat answers from the findings and the story alone, says so under the answer, and the
tools list says the server didn't accept them. *off* never offers tools; *on* always does.

API
---

- ``GET /api/v1/chat-tools``: the tools and whether the configured LLM takes them.
- ``POST /api/v1/files/{fileId}/chat-turns``: ask; returns ``201`` with the turn ``RUNNING``.
- ``GET /api/v1/files/{fileId}/chat-turns/{turnId}``: its steps so far, then the answer
  (``DONE``) or the error (``FAILED``). Turns are kept for 30 minutes.
