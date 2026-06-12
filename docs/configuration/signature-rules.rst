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
       payload_regex:             # optional: payload regex patterns
         - pattern: <regex>
           case_insensitive: <bool>   # optional, default false
       match_all: <bool>          # optional: AND all payload_contains / payload_regex entries
       device_type: <string>      # optional: pin device type for matched IPs

Execution Semantics
--------------------

A rule fires for a given conversation when **all** of the following hold:

1. Every field in ``match`` matches the conversation's attributes.
2. If ``payload_contains`` is present:

   - Default (``match_all`` absent or ``false``): **at least one** pattern
     matches the payload of any packet in the conversation.
   - With ``match_all: true``: **all** patterns match (each may match a
     different packet).

3. If ``payload_regex`` is present:

   - Default: **at least one** pattern matches the decoded payload of any packet.
   - With ``match_all: true``: **all** patterns match.

If ``payload_contains`` and ``payload_regex`` are both specified, both must
pass (AND). All three conditions — ``match``, ``payload_contains``, and
``payload_regex`` — are ANDed together.

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

Exact match against either the **JA3C** (client) fingerprint or the **JA3S**
(server) fingerprint recorded by nDPI. The rule fires if either hash matches,
so a single rule can flag a fingerprint regardless of which side of the TLS
handshake it appeared on. Only populated when nDPI analysis is enabled.

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

Patterns are searched across the **raw payload bytes of each individual
packet** in the conversation (stored as hex strings). A match on any single
packet in the conversation is sufficient.

``payload_regex``
~~~~~~~~~~~~~~~~~

List of regular expression objects. Each entry requires:

- ``pattern: "<regex>"`` — a standard Java regular expression applied against
  the **ASCII/UTF-8 decoded payload** of each packet.

Optional per entry:

- ``case_insensitive: true`` — enables case-insensitive (and Unicode-aware)
  matching. Default ``false``.

.. code-block:: yaml

   payload_regex:
     - pattern: "Authorization:\\s*Basic\\s+[A-Za-z0-9+/=]+"
       case_insensitive: true
     - pattern: "eyJ[A-Za-z0-9_\\-]+\\.eyJ[A-Za-z0-9_\\-]+\\.[A-Za-z0-9_\\-]+"

A match on any single packet in the conversation is sufficient (OR across
packets). Use ``match_all: true`` to require all entries to match.

.. note::

   Payloads are capped at 64 KB per packet before regex evaluation to prevent
   catastrophic backtracking. Regex syntax errors are caught by the browser
   editor on save — an inline error identifies the rule name and pattern index.

``payload_regex`` can be combined with ``payload_contains`` and/or ``match``
in the same rule; all specified conditions must be satisfied.

``match_all``
~~~~~~~~~~~~~

Boolean. Default ``false``. When ``true``, **all** ``payload_contains`` entries
and **all** ``payload_regex`` entries must each find a match somewhere in the
conversation's packets (AND semantics). When ``false`` or absent, any single
entry matching is sufficient (OR semantics).

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

The browser editor performs two levels of validation on save:

1. **YAML syntax** — the file must be valid YAML.
2. **Regex syntax** — every ``payload_regex`` pattern is compiled and any
   invalid pattern returns an inline error identifying the rule name and
   pattern index (e.g. ``Rule "my_rule": invalid regex at payload_regex[0]: …``).

Semantic errors (e.g. invalid severity, malformed CIDR) are reported in the
backend logs:

.. code-block:: bash

   docker compose logs -f tracepcap-backend
