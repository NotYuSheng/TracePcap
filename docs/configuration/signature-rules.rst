Signature Rule Authoring Guide
================================

This page is a deep-dive reference for writing TracePcap custom detection
rules. For a quick overview, see :doc:`../features/custom-signatures`.

Rule Structure
--------------

Each rule is a YAML mapping under the top-level ``signatures`` list:

.. code-block:: yaml

   signatures:
     - name: <string>             # required
       description: <string>      # optional, shown in UI tooltip
       severity: <level>          # required: low | medium | high | critical
       match:                     # optional: one or more match fields (AND)
         <field>: <value>
         ...
       payload_contains:          # optional: payload byte patterns
         - ascii: <string>
         - hex: <hex-string>
       match_all: <bool>          # optional: if true, all payload_contains entries must match
       device_type: <string>      # optional: pin device type for matched IPs

Execution Semantics
--------------------

A rule fires for a given conversation when **all** of the following hold:

1. Every field in ``match`` matches the conversation's attributes.
2. If ``payload_contains`` is present:

   - Default (``match_all`` absent or ``false``): **at least one** pattern
     matches the payload.
   - With ``match_all: true``: **all** patterns match the payload.

If both ``match`` and ``payload_contains`` are specified, both conditions
must be satisfied (AND).

Field Reference
---------------

``name``
~~~~~~~~

Required. The identifier shown as a badge in the UI.

- Must be unique across all rules.
- Use underscores instead of spaces (e.g. ``known_c2_ip``).
- Avoid special characters.

``description``
~~~~~~~~~~~~~~~

Optional. A human-readable sentence explaining what the rule detects.
Displayed in the UI as a tooltip on the badge.

``severity``
~~~~~~~~~~~~

Required. One of: ``low``, ``medium``, ``high``, ``critical``.

Controls badge color. See :doc:`../features/custom-signatures` for the color
mapping.

``match.ip``
~~~~~~~~~~~~

Exact match against the conversation's ``srcIp`` **or** ``dstIp``.

.. code-block:: yaml

   match:
     ip: "203.0.113.42"

``match.cidr``
~~~~~~~~~~~~~~

CIDR range match against ``srcIp`` **or** ``dstIp``.

.. code-block:: yaml

   match:
     cidr: "198.51.100.0/24"

Both IPv4 and IPv6 CIDR notation are supported.

``match.srcPort`` / ``match.dstPort``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Exact integer port match against the conversation's source or destination port.

.. code-block:: yaml

   match:
     srcPort: 67
     dstPort: 4444

``match.ja3``
~~~~~~~~~~~~~

Exact match against the JA3S fingerprint hash recorded by nDPI.
Only populated when nDPI analysis is enabled and a TLS ServerHello is observed.

.. code-block:: yaml

   match:
     ja3: "82f0d8a75fa483d1cfe4b7085b784d7e"

Obtain hashes from threat intelligence feeds. The ``demo_all_rules.pcap``
sample file contains a crafted TLS exchange to test JA3 matching.

``match.hostname``
~~~~~~~~~~~~~~~~~~

Match against the SNI (Server Name Indication) hostname extracted from the
TLS ClientHello.

- **Exact match**: ``"mobile.pipe.aria.microsoft.com"``
- **Wildcard prefix**: ``"*.microsoft.com"`` — matches ``foo.microsoft.com``,
  ``bar.baz.microsoft.com``, etc. (any depth).

.. code-block:: yaml

   match:
     hostname: "*.evil.example.com"

``match.app``
~~~~~~~~~~~~~

Case-insensitive match against the nDPI application name
(e.g. ``"Telegram"``, ``"TOR"``, ``"DNS"``, ``"BitTorrent"``).

``match.protocol``
~~~~~~~~~~~~~~~~~~

Case-insensitive match against the transport protocol
(e.g. ``"TCP"``, ``"UDP"``, ``"ICMP"``).

``payload_contains``
~~~~~~~~~~~~~~~~~~~~

List of byte pattern objects. Each entry has exactly one key:

- ``ascii: "string"`` — search for the UTF-8 bytes of the given string.
- ``hex: "deadbeef"`` — search for the given hex byte sequence.
  The ``0x`` prefix and space separators are optional (``"0xDE 0xAD"`` is
  equivalent to ``"dead"``).

Patterns are searched across the **reassembled payload** of the conversation
(not just individual packets).

``match_all``
~~~~~~~~~~~~~

Boolean. Default ``false``. When ``true``, all ``payload_contains`` entries
must match (AND semantics). When ``false`` or absent, any single entry
matching is sufficient (OR semantics).

``device_type``
~~~~~~~~~~~~~~~

Optional string. When the rule fires, all IP addresses involved in the
matching conversation are assigned this device type in the Network
Visualization and Conversations filter.

Standard values: ``ROUTER``, ``MOBILE``, ``LAPTOP_DESKTOP``, ``SERVER``,
``IOT``, ``UNKNOWN``.

Custom strings are accepted (e.g. ``"PLC"``, ``"CCTV Camera"``).

Editing Rules at Runtime
-------------------------

Rules can be edited without restarting TracePcap:

1. Navigate to **Custom Detection Rules** in the navbar.
2. Edit the YAML in the browser editor.
3. Click **Save**.
4. Re-analyse or upload a new PCAP — the updated rules are applied immediately.

Alternatively, edit ``/app/config/signatures.yml`` directly inside the backend
container. The file is read fresh on every analysis run.

Validating Rules
----------------

The browser editor validates YAML syntax on save and highlights errors inline.
Semantic errors (e.g. invalid severity, malformed CIDR) are reported in the
backend logs:

.. code-block:: bash

   docker compose logs -f tracepcap-backend
