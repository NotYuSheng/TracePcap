Custom Signature Rules
======================

TracePcap supports user-defined detection rules that are matched against
every conversation after nDPI analysis. Matched rule names appear as
color-coded badges in the Conversations tab and Overview, alongside nDPI's
built-in detections.

How It Works
------------

Rules are stored in the **database**, as global rules that apply to every
capture. They're edited on the **System** page, under **Detection rules**
(the **Custom Detection Rules** button in the header links there too).

- **Add rule** opens a form: name, severity, description, the match fields,
  and payload patterns. Fields are checked as you type, and anything the
  server rejects (a CIDR that isn't one, a regex that doesn't compile) is
  shown next to its field.
- Each rule has an **on/off switch**, so a rule can be paused without losing
  it, and shows who last changed it, when, and its version.
- New captures are checked against the enabled rules when they're
  analysed. Captures analysed earlier are **not** re-checked automatically
  when a rule is added or changed; see `Keeping matches up to date`_.
- **Who can edit** is a permission (*Edit global detection rules*, analysts by
  default; see :ref:`settings-permissions`). Everyone can view the rules.
- Every create, edit and delete is recorded in the **audit log**, with the
  rule before and after.

**Export** downloads every rule as a YAML file, in the format below.
**Import** reads such a file, or an old ``signatures.yml``: rules are matched
to existing ones by name, and *Replace* also deletes rules the file doesn't
contain. If any rule in the file is invalid, nothing is imported, and every
problem is listed. Export and import are for backups and for moving rules
between installs; the database is what TracePcap uses.

**Upgrading from ``signatures.yml``.** Earlier versions kept the rules in a
file in the ``config_data`` volume. On the first start after upgrading,
TracePcap imports that file once. A rule the editor would reject (for
example a regex that doesn't compile) is imported **disabled**, with the
reason in its description, so nothing is lost and nothing starts matching
differently. The audit log records the import. If you had pointed
``SIGNATURES_PATH`` at a different file, import it with **Import** instead.

Rules for one capture
---------------------

Sometimes a rule only makes sense for one capture: "in this capture,
``10.0.0.53`` is the sanctioned DNS server", or a pattern you're testing
before you trust it everywhere. A capture's **Overview** has **Rules for this
capture**:

- **Add rule** opens the same form as global rules. The rule flags
  conversations in this capture only, **straight away**, with no re-apply,
  and wherever the capture is viewed, including inside a network where it's a
  snapshot.
- Each rule can be switched off, edited, deleted, or **promoted**.
- **Promote** makes a global copy, so the rule flags every capture. You
  choose whether to keep the capture's rule as well. The copy is checked
  against this capture at once; other captures show as out of date until the
  rules are re-applied.
- A capture rule's name can't be the same as a global rule's, since both label
  the same capture. A promoted copy is the exception: it's meant to label the
  same thing.
- Who can edit capture rules is its own permission (*Edit capture detection
  rules*, analysts by default). Promoting needs the global-rules permission
  too. Every change is in the audit log.

**Each match says where it comes from.** Rule badges in the conversations
table, the conversation details, the filter and the Overview end in their
scope: *global* or *capture*.

Keeping matches up to date
--------------------------

TracePcap records, for each capture, which version of each rule it was
checked against. When you add a rule or change what one matches, captures
checked before stay as they were, and are shown as **out of date**:

- The **Detection rules** tab says how many captures haven't been checked
  against the current rules, with **Re-apply** to check them all.
- A capture's **Overview** names the rules it's out of date for, with
  **Re-apply to this capture**.

Re-apply runs in the background, with its progress shown, one capture at a
time. It's safe to run again, and a capture is never left half-updated. It
needs the same permission as editing rules, and is recorded in the audit
log. If the backend restarts mid-run, the job is marked *interrupted*; start
it again to finish.

Some changes apply **at once**, everywhere, with no re-apply: switching a
rule off hides its matches, switching it back on shows them again, renaming
it relabels them, and deleting it removes them.

**Captures whose packets were deleted.** Rules that look inside packets
(``payload_contains``, ``payload_regex``) need the capture's raw packets. If
retention has deleted them (``PACKET_RETENTION_HOURS``), Re-apply can't
re-check those rules, so their old matches are dropped and the capture says
**couldn't re-check** rather than showing results from an older rule.

**After upgrading,** captures analysed by an earlier version show as out of
date: which rule versions produced their matches isn't known. Their existing
matches stay visible; Re-apply brings them up to date.

The **Network Labels** tab of the **Custom Detection Rules** dialog defines
CIDR-to-label mappings used in the Network Visualization grouping mode (see
`Network Labels`_ below).

.. _Network Labels:

.. tip::

   ``signatures.sample.yml`` in the repository root covers every match field
   with annotated examples. Import it from **Detection rules** to get
   started, then adjust the rules to your environment.

.. note::

   ``device_type`` (setting a matched host's device type) is still honoured
   for existing rules, but can't be set in the editor any more. Device types
   are moving to classification signals (#926).

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

The **Network Labels** tab (in the **Custom Detection Rules** dialog) maps
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
