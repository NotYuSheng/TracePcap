Sample Files
============

The ``sample-files/`` directory contains example PCAP files and generator
scripts to help you test and explore TracePcap's features.

Included Files
--------------

.. list-table::
   :header-rows: 1
   :widths: 35 65

   * - File
     - Description
   * - ``atm_capture1.cap``
     - ATM network traffic sample. Useful for testing protocol parsing and
       multi-protocol support.
   * - ``free5gc.pcap``
     - 5G core network (free5GC) traffic sample. Demonstrates TracePcap's
       handling of GTP tunnelling and 5G control-plane protocols.
   * - ``demo_all_rules.pcap``
     - Crafted PCAP that triggers all 17 custom signature demo rules defined
       in ``signatures.sample.yml``. Use this to verify that custom signature
       matching is working correctly.
   * - ``monitor_large/week1_baseline.pcap`` … ``week8_near_baseline.pcap``
     - Eight weekly captures from the **Office Audit demo scenario**. Used to
       demonstrate the Network Monitor, subnet detection, node role annotation,
       and AI-generated insights. See below for full details.

Generating ``demo_all_rules.pcap``
------------------------------------

The generator script ``sample-files/gen_demo.py`` synthesises the demo PCAP
programmatically using Scapy. To regenerate it:

.. code-block:: bash

   pip install scapy
   python3 sample-files/gen_demo.py

The script produces ``sample-files/demo_all_rules.pcap``.

Walkthrough: Custom Signature Demo
------------------------------------

1. Copy ``signatures.sample.yml`` into the TracePcap browser editor:
   Navigate to **Custom Detection Rules** → paste the file contents → **Save**.

2. Upload ``demo_all_rules.pcap`` with **nDPI Analysis** enabled.

3. Once analysis completes, open the **Conversations** tab. You should see
   all 17 custom signature badges firing across the conversations.

4. Open the **Overview** tab to see aggregate signature match counts.

5. Explore the **Network Visualization** to see risk indicators on relevant
   nodes.

----

Office Audit Demo Scenario
--------------------------

The ``monitor_large/`` directory contains eight synthetic weekly captures that
model a realistic external audit engagement. The auditor receives one PCAP per
week from the client — no network documentation, no asset inventory. Everything
is pieced together from the traffic itself.

Over the eight-week audit period, a string of internal policy violations
escalates and then subsides after an audit notice is issued.

Scenario Background
~~~~~~~~~~~~~~~~~~~

The network is a mid-sized office with four segments:

.. list-table::
   :header-rows: 1
   :widths: 20 20 60

   * - Subnet
     - Range
     - Purpose
   * - Staff workstations
     - ``10.0.1.0/24``
     - Employee desktops and laptops (corporate-managed)
   * - Servers
     - ``10.0.2.0/24``
     - File server (SMB), mail server (SMTP/IMAP), internal web server (HTTP)
   * - Printers / peripherals
     - ``10.0.3.0/24``
     - Floor printers (IPP/LPD)
   * - WiFi / BYOD
     - ``10.0.4.0/24``
     - Wireless access — both managed laptops and personal devices

Named Devices
~~~~~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 20 20 60

   * - Device
     - IP
     - Role
   * - Gateway
     - ``10.0.1.1``
     - Corporate router / internet gateway
   * - File Server
     - ``10.0.2.10``
     - Internal file server (SMB :445)
   * - Mail Server
     - ``10.0.2.20``
     - Internal mail server (SMTP :25, IMAP :143)
   * - Web Server
     - ``10.0.2.30``
     - Internal intranet (HTTP :80)
   * - Printer A / B
     - ``10.0.3.5`` / ``10.0.3.6``
     - Floor printers (IPP :631)
   * - WS_ALICE
     - ``10.0.1.10``
     - Alice — compliant employee, normal traffic throughout
   * - WS_BOB
     - ``10.0.1.11``
     - Bob — FTP exfiltration to external IP (weeks 4–6)
   * - WS_CAROL
     - ``10.0.1.12``
     - Carol — joins week 3; Telnet to file server (cleartext credentials)
   * - WS_DAVE
     - ``10.0.1.13``
     - Dave — joins week 5; normal new employee
   * - LAPTOP_BOB
     - ``10.0.4.20``
     - Bob's personal laptop on WiFi — WireGuard VPN bypass + BitTorrent (weeks 2–6)
   * - MOBILE_EVE
     - ``10.0.4.30``
     - Eve's personal mobile — joins week 4; remains on network through week 8
   * - SHADOW_DEV
     - ``10.0.4.50``
     - Unknown device (Raspberry Pi OUI); ARP-spoofs Bob's IP; weeks 5–6 only

Story Arc
~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 10 30 60

   * - Week
     - File
     - What happens
   * - 1
     - ``week1_baseline.pcap``
     - Clean baseline — normal office day. HTTP/HTTPS to internet, SMB to file
       server, SMTP/IMAP to mail server, DNS, print jobs. ~170 hosts.
   * - 2
     - ``week2_personal_laptop_vpn.pcap``
     - Bob's personal laptop (``dc:a6:32`` OUI — Raspberry Pi Ltd) appears on
       WiFi. Immediately starts a WireGuard VPN tunnel to an external endpoint,
       bypassing the corporate proxy. **Signals: MAC_ADDED, VPN_DRIFT new.**
   * - 3
     - ``week3_telnet_bittorrent.pcap``
     - Carol's workstation joins. Carol uses Telnet to connect to the file server —
       cleartext credentials visible in payload. Bob's laptop begins BitTorrent
       traffic. **Signals: MAC_ADDED (Carol), PROTOCOL_ADDED (Telnet),
       APP_ADDED (BitTorrent).**
   * - 4
     - ``week4_ftp_exfil_gateway_change.pcap``
     - Bob's workstation starts FTP transfers to ``192.0.2.99`` (external IP, not
       a known corporate server) — credentials and filename ``report_q4.pdf``
       visible in payload. ISP failover causes a gateway change.
       Eve's personal mobile joins WiFi. **Signals: PROTOCOL_ADDED (FTP),
       GATEWAY_CHANGE, MAC_ADDED (Eve's mobile).**
   * - 5
     - ``week5_shadow_device_arp_spoof.pcap``
     - An unknown device with a Raspberry Pi OUI (``b8:27:eb``) appears on WiFi
       with no hostname in DNS. It sends a gratuitous ARP claiming Bob's
       workstation IP — then connects to the file server over SMB using that
       identity. Dave's workstation joins normally.
       **Signals: MAC_ADDED (shadow device, Dave), IP_MAC_DRIFT CRITICAL
       (ARP spoof).**
   * - 6
     - ``week6_peak_violations.pcap``
     - Peak violation week. FTP exfiltration, BitTorrent, WireGuard VPN,
       Telnet, and the shadow device are all simultaneously active. Shadow
       device also uses Telnet to the file server.
       **Signals: no new signals — all violations continue.**
   * - 7
     - ``week7_violations_drop_gateway_back.pcap``
     - Audit notice issued. FTP stops, BitTorrent stops, WireGuard stops, Telnet
       stops. Shadow device disappears. Gateway returns to the primary ISP.
       Bob's personal laptop stays connected but is idle.
       **Signals: GATEWAY_CHANGE (back to primary), VPN_DRIFT gone,
       MAC absent (shadow device), APP_ADDED gone (BitTorrent), Telnet gone.**
   * - 8
     - ``week8_near_baseline.pcap``
     - Near-baseline. All core violations resolved. Bob's personal laptop and
       Eve's mobile remain on the network — the personal-device policy has not
       been enforced. **Signals: none — stable.**

Policy Violations Summary
~~~~~~~~~~~~~~~~~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 35 15 50

   * - Violation
     - Weeks active
     - Evidence in capture
   * - WireGuard VPN bypass (LAPTOP_BOB)
     - 2–6
     - UDP :51820 to ``198.51.100.50``; WireGuard handshake payload
   * - BitTorrent P2P (LAPTOP_BOB)
     - 3–6
     - UDP :6881 BitTorrent DHT ping payloads
   * - Telnet to file server — cleartext (WS_CAROL)
     - 3–6
     - TCP :23 to ``10.0.2.10``; ``login: admin / Password: P@ssw0rd`` in payload
   * - FTP exfiltration to external IP (WS_BOB)
     - 4–6
     - TCP :21 to ``192.0.2.99``; ``USER ftpuser / STOR report_q4.pdf`` in payload
   * - Unauthorised shadow device (SHADOW_DEV, RPi OUI)
     - 5–6
     - MAC ``b8:27:eb:77:77:07``; no DNS hostname; accesses file server
   * - ARP spoofing — shadow device claims Bob's IP
     - 5
     - Gratuitous ARP: ``b8:27:eb:77:77:07`` announces ``10.0.1.11``
   * - Personal devices on corporate WiFi (LAPTOP_BOB, MOBILE_EVE)
     - 2–8
     - Consumer-OUI MACs on ``10.0.4.0/24``; no hostname in DNS

Generating the Office Audit PCAPs
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The generator requires Scapy. The ``monitor_large/`` directory is pre-populated,
but you can regenerate the files at any time:

.. code-block:: bash

   pip install scapy
   cd sample-files
   python3 gen_monitor_large.py

Walkthrough: Office Audit Demo
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Step 1 — Upload and analyse all eight files**

Upload each ``week*.pcap`` file via the standard upload flow with nDPI analysis
enabled. Wait for all eight to reach status *Completed*.

**Step 2 — Create a Network Monitor session**

Navigate to **Monitor** → **Create Network** → name it
``Office Audit — Corp HQ`` and set the description to::

    Corporate HQ office network — weekly PCAP captures from the managed switch spanning eight weeks. Segment covers staff workstations, servers, printers, and BYOD WiFi.

The description is included in the LLM prompt when generating Network Insights,
giving the model useful context about the environment and capture method.

**Step 3 — Add snapshots**

Click **Add Snapshot** and add all eight files. The Monitor orders them by
capture time automatically. Change events appear as soon as the second snapshot
is added.

**Step 4 — Detect subnets**

In the **Subnet Definitions** panel, select ``week1_baseline.pcap`` from the
dropdown and click **Detect Subnets**. The engine should propose four candidates:

- ``10.0.1.0/24`` — staff workstations
- ``10.0.2.0/24`` — servers
- ``10.0.3.0/24`` — printers
- ``10.0.4.0/24`` — WiFi / BYOD

Save all four and add labels. The IP Addresses drift panel will now group all
IPs by subnet.

**Step 5 — Annotate key devices**

Click IP badges in the drift panels to open the Entity Detail modal. Assign
role labels to the named devices:

.. list-table::
   :header-rows: 1
   :widths: 25 75

   * - IP
     - Suggested role label
   * - ``10.0.2.10``
     - File Server (SMB)
   * - ``10.0.2.20``
     - Mail Server (SMTP/IMAP)
   * - ``10.0.2.30``
     - Internal Web Server
   * - ``10.0.3.5``
     - Floor Printer A (IPP)
   * - ``10.0.3.6``
     - Floor Printer B (IPP)
   * - ``10.0.1.10``
     - Alice — Staff Workstation (compliant)
   * - ``10.0.1.11``
     - Bob — Staff Workstation (FTP exfil weeks 4–6)
   * - ``10.0.1.12``
     - Carol — Staff Workstation (Telnet weeks 3–6)
   * - ``10.0.4.20``
     - Bob's Personal Laptop (VPN bypass + BitTorrent)
   * - ``10.0.4.50``
     - Unknown Device — Raspberry Pi OUI (shadow device)

Use **Suggest with AI** on ``10.0.4.50`` to see how the LLM characterises the
device from its traffic behaviour alone (unusual OUI, ARP spoofing, SMB + Telnet
to internal servers, no hostname).

**Step 6 — Add external events**

In the **External Events** panel, log the audit milestone that explains the
behavioural shift:

- Date: start of week 7 — *"Audit notice issued to staff — policy violations
  flagged for remediation"*

**Step 7 — Generate insights**

Click **Generate Insights**. With device roles and the external event in
context, the LLM should correlate the violation drop-off in week 7 with the
audit notice, identify the shadow device as the highest-severity finding, and
surface the lingering personal-device policy gap in week 8.

Adding Your Own PCAP Files
--------------------------

Place any ``.pcap``, ``.pcapng``, or ``.cap`` file in ``sample-files/`` and
upload it via the TracePcap UI. There is no restriction on the content —
any valid capture file is accepted.
