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

Click **Custom Detection Rules** in the navbar to open the built-in YAML
editor. Changes are saved immediately.

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
     - Exact JA3S fingerprint hash (nDPI 5.x)
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

In addition to ``match`` fields, rules can search raw packet payloads:

.. code-block:: yaml

   payload_contains:
     - ascii: "GET /admin"       # plain ASCII text
     - hex: "255044462d"         # hex bytes (%PDF-)

Multiple ``payload_contains`` entries are **OR-matched** by default. Set
``match_all: true`` on the rule to require **all** patterns (AND):

.. code-block:: yaml

   - name: http_post_with_token
     match_all: true
     payload_contains:
       - ascii: "POST /"
       - ascii: "token"

``payload_contains`` can be combined with ``match`` fields — both conditions
must be satisfied for the rule to fire.

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

     # Cleartext credential detection
     - name: cleartext_credentials
       severity: critical
       payload_contains:
         - ascii: "Authorization: Basic"
         - ascii: "password="

See ``signatures.sample.yml`` for a full set of 17 annotated example rules
covering every match field. The script ``sample-files/gen_demo.py`` generates
a PCAP that triggers all demo rules at once.

For a deep-dive rule authoring guide, see :doc:`../configuration/signature-rules`.
