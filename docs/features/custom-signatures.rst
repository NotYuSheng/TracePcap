Custom Signature Rules
======================

TracePcap supports user-defined YAML detection rules that are matched against
every conversation after nDPI analysis. Matched rule names appear as
color-coded badges in the Conversations tab and Overview, alongside nDPI's
built-in detections.

How It Works
------------

Rules are stored inside a Docker named volume (``config_data``) at
``/app/config/signatures.yml`` inside the backend container. The file is
reloaded on every analysis run — **no restart is required** after editing.

Click **Custom Detection Rules** in the navbar to open a modal with two tabs:

- **Detection Rules** — the built-in YAML editor for ``signatures.yml``.
  Changes are saved immediately and take effect on the next analysis run.
- **Network Labels** — define CIDR-to-label mappings used in the Network
  Visualization grouping mode (see `Network Labels`_ below).

.. _Network Labels:

.. tip::

   ``signatures.sample.yml`` in the repository root is a reference template
   covering every match field with annotated examples. Paste it into the
   browser editor to get started, then modify to suit your environment.

Rule Format
-----------

.. code-block:: yaml

   signatures:
     - name: rule_name_shown_in_ui   # badge label — use underscores, no spaces
       description: Human-readable description
       severity: low                  # low | medium | high | critical
       match:
         ip: "203.0.113.42"           # match against srcIp OR dstIp

A rule fires when **all** specified ``match`` fields are satisfied.
All fields are optional — mix and match as needed.

Match Fields
------------

.. list-table::
   :header-rows: 1
   :widths: 18 12 45 25

   * - Field
     - Type
     - Description
     - Example
   * - ``ip``
     - string
     - Exact match against srcIp or dstIp
     - ``"203.0.113.42"``
   * - ``cidr``
     - string
     - CIDR range match against srcIp or dstIp
     - ``"10.0.0.0/8"``
   * - ``srcPort``
     - integer
     - Exact source port
     - ``67``
   * - ``dstPort``
     - integer
     - Exact destination port
     - ``4444``
   * - ``ja3``
     - string
     - Exact match against **either** the JA3C (client) or JA3S (server)
       fingerprint hash recorded by nDPI
     - ``"82f0d8a75fa483d1cfe4b7085b784d7e"``
   * - ``hostname``
     - string
     - Exact or wildcard SNI hostname. ``*.evil.com`` matches any subdomain
       at any depth.
     - ``"*.evil.com"``
   * - ``app``
     - string
     - Case-insensitive nDPI application name
     - ``"Telegram"``, ``"TOR"``, ``"DNS"``
   * - ``protocol``
     - string
     - Case-insensitive transport protocol
     - ``"TCP"``, ``"UDP"``, ``"ICMP"``

Payload Matching
----------------

In addition to ``match`` fields, rules can inspect raw packet payloads using
byte-string patterns (``payload_contains``) or regular expressions
(``payload_regex``). Both can be combined with ``match`` fields in the same
rule — all conditions must be satisfied for the rule to fire.

``payload_contains``
~~~~~~~~~~~~~~~~~~~~

.. code-block:: yaml

   payload_contains:
     - ascii: "GET /admin"       # plain ASCII text
     - hex: "255044462d"         # hex bytes (%PDF-)

Patterns are searched against the raw payload bytes of each packet in the
conversation. A match on any single packet is sufficient.

Multiple entries are **OR-matched** by default. Set ``match_all: true`` on the
rule to require **all** patterns (AND):

.. code-block:: yaml

   - name: http_post_with_token
     match_all: true
     payload_contains:
       - ascii: "POST /"
       - ascii: "token"

``payload_regex``
~~~~~~~~~~~~~~~~~

Regular expressions can be used in place of (or alongside) ``payload_contains``:

.. code-block:: yaml

   payload_regex:
     - pattern: "Authorization:\\s*Basic\\s+[A-Za-z0-9+/=]+"
       case_insensitive: true    # optional, default false

Patterns are standard Java regular expressions applied against the
**ASCII/UTF-8 decoded payload** of each packet. A match on any single packet
in the conversation is sufficient.

- ``case_insensitive: true`` enables case-insensitive matching for that entry.
- The same ``match_all`` flag applies: set ``match_all: true`` on the rule to
  require **all** ``payload_regex`` entries to match.
- Regex syntax errors are caught when the file is saved — the editor displays
  an inline error identifying the rule and the offending pattern index.

``payload_contains`` and ``payload_regex`` can coexist in the same rule; both
must match (AND).

Device Type Override
--------------------

A rule can pin the device type of all IPs involved in a matching conversation:

.. code-block:: yaml

   - name: cctv_camera
     description: Known CCTV camera
     severity: low
     device_type: "CCTV Camera"
     match:
       ip: "192.168.1.50"

Standard values: ``ROUTER``, ``MOBILE``, ``LAPTOP_DESKTOP``, ``SERVER``,
``IOT``, ``UNKNOWN``. Custom strings (e.g. ``"PLC"``, ``"CCTV Camera"``) are
also accepted.

Severity Colors
---------------

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Severity
     - Badge color
   * - ``critical``
     - Red
   * - ``high``
     - Orange
   * - ``medium``
     - Amber / Yellow
   * - ``low``
     - Purple

Examples
--------

.. code-block:: yaml

   signatures:

     # Flag a known C2 IP
     - name: known_c2_ip
       description: Known command-and-control server
       severity: high
       match:
         ip: "203.0.113.42"

     # Flag all traffic to a suspicious subnet
     - name: flagged_subnet
       severity: medium
       match:
         cidr: "198.51.100.0/24"

     # Detect DNS over TCP (possible zone transfer or tunnelling)
     - name: dns_over_tcp
       severity: medium
       match:
         app: "DNS"
         protocol: TCP

     # Wildcard hostname match
     - name: blocked_domain
       severity: high
       match:
         hostname: "*.malware.example.com"

     # JA3S fingerprint from a threat-intel feed
     - name: suspicious_tls_fingerprint
       severity: critical
       match:
         ja3: "a0e9f5d64349fb13191bc781f81f42e1"

     # Cleartext credential detection (payload_contains)
     - name: cleartext_credentials
       severity: critical
       payload_contains:
         - ascii: "Authorization: Basic"
         - ascii: "password="

     # Regex: HTTP Basic-auth header (case-insensitive)
     - name: http_basic_auth_regex
       severity: critical
       payload_regex:
         - pattern: "Authorization:\\s*Basic\\s+[A-Za-z0-9+/=]+"
           case_insensitive: true

     # Regex: SQL injection probe on plain HTTP (match + payload_regex)
     - name: sql_injection_probe
       severity: critical
       match:
         protocol: TCP
         dstPort: 80
       payload_regex:
         - pattern: "(?:UNION\\s+SELECT|DROP\\s+TABLE|'\\s*OR\\s*'1'\\s*=\\s*'1)"
           case_insensitive: true

See ``signatures.sample.yml`` for a full set of 21 annotated example rules
covering every match field, payload byte pattern, and regex pattern. The script
``sample-files/gen_demo.py`` generates ``demo_all_rules.pcap``, which triggers
all 21 rules at once.

For a deep-dive rule authoring guide, see :doc:`../configuration/signature-rules`.

Network Labels
--------------

The **Network Labels** tab (in the same **Custom Detection Rules** modal) maps
individual IP addresses or CIDR ranges to human-readable organisation labels.
These labels are used as a grouping strategy in the **Network Visualization**
— enabling you to cluster nodes by network segment rather than by ASN or
country.

How to Add a Label
~~~~~~~~~~~~~~~~~~

1. Open **Custom Detection Rules** in the navbar.
2. Switch to the **Network Labels** tab.
3. Enter a label name (e.g. ``Corporate LAN``, ``DMZ``, ``Guest Wi-Fi``) and
   a CIDR range (e.g. ``10.0.1.0/24``) or individual IP (e.g. ``10.0.1.5``).
4. Click **Add**.

Labels are stored in the database and persist across sessions. Multiple CIDR
entries can share the same label to group non-contiguous ranges under one name.

Specificity Priority
~~~~~~~~~~~~~~~~~~~~

When an IP matches multiple CIDR rules, the **most specific** (longest prefix
length) rule wins. For example, if ``10.0.1.0/24`` is labelled ``Corporate LAN``
and ``10.0.1.100/32`` is labelled ``Print Server``, the IP ``10.0.1.100`` will
be assigned ``Print Server``.

Using Labels in the Network Visualization
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

In the Network Visualization, select **Network Labels** from the grouping
dropdown. Nodes are clustered by label. IPs that fall within any labelled CIDR
appear grouped; IPs not covered by any rule appear individually.

The graph is filtered to show conversations where **at least one endpoint** is
a labelled IP — unlabelled-only traffic is suppressed when this grouping mode
is active.
