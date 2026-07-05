Label Staleness Detection
=========================

TracePcap lets analysts attach **labels** to three kinds of entities:

- **IP addresses** — an operational *role* (e.g. "Domain Controller").
- **Devices (MAC addresses)** — an operational *role* (e.g. "Site PLC").
- **Subnet definitions** — a *label + description* naming a CIDR (e.g. "IoT sensor
  cluster").

A label is only as good as the moment it was written. As a network is observed
across successive captures, the thing behind a label can change — a host starts
speaking new protocols, a CIDR fills up with a different class of device. When
that happens, TracePcap automatically flags the label **stale** so an analyst can
re-confirm or update it, rather than silently trusting a label that no longer
fits what the traffic shows.

This page documents exactly how that flag is raised. The short version:

.. note::

   Staleness is **fully deterministic**. It is a plain set-difference between two
   point-in-time snapshots of *observed* properties. There is **no LLM, no machine
   learning, no scoring, and no hardcoded list of "significant" protocols**. Any
   protocol can trigger a flag; none is privileged.

.. important::

   Staleness only exists in **Monitor mode**, where a network has an ordered
   series of snapshots to compare across. A single PCAP analysed on its own has
   nothing to drift against.


How it works
------------

The mechanism has three moving parts, identical in shape for all three entity
types:

1. **Baseline capture.** When an analyst *confirms* a label, TracePcap snapshots
   the entity's key *observed properties* at that moment and stores them as the
   **baseline** (alongside the file the baseline was computed from and a
   timestamp).

2. **Re-validation.** Each time a new snapshot is added to the network (or the
   snapshot chain is reordered/recomputed), the entity's *current* properties are
   recomputed from the newest capture and compared against the stored baseline.

3. **Drift → stale.** If the current properties differ from the baseline, the
   label is marked stale: a ``stale_since`` timestamp is set and a human-readable
   ``stale_fields`` list records *what* changed. The flag persists across later
   snapshots until the analyst resolves it — it does not clear just because a
   still-later snapshot happens to match again.

Resolving a stale flag is an explicit analyst action:

- **Update the label** — re-labelling re-captures a fresh baseline.
- **Dismiss ("still correct")** — keeps the label and re-baselines against the
  current composition, accepting the new behaviour as expected.


What "properties" means per entity type
---------------------------------------

The comparison is a set-difference, but *which sets* are compared depends on the
entity. "Dominant" always means **most frequent by observed count**, taken as the
top-N via ``GROUP BY … ORDER BY COUNT(*) DESC LIMIT N`` over that capture. It is
**not** an allow-list of interesting protocols — it is simply whatever was most
common in the traffic.

.. list-table::
   :header-rows: 1
   :widths: 18 44 20 18

   * - Entity
     - Properties compared
     - "Dominant" cutoff
     - Flags on
   * - **IP address**
     - MAC address · top protocols · external organisations contacted
     - top 5 protocols
     - additions only
   * - **Device (MAC)**
     - Device type · top protocols · external organisations contacted
     - top 5 protocols
     - additions only
   * - **Subnet (CIDR)**
     - Dominant member **device types** · dominant member **protocols**
     - top 6 device types, top 8 protocols
     - additions **and** removals

.. note::

   **Direction asymmetry.** For IP and device roles, only *new* signals raise a
   flag — a new protocol, a new external org, or a changed MAC. A protocol simply
   *disappearing* does not, on its own, mark a role stale. For subnet definitions,
   both directions count: a device type or protocol **appearing** *or* **going
   away** is treated as composition drift, because a subnet's purpose is about the
   mix of what lives in it.

External organisations (IP/device roles) are resolved from the geo cache — the
distinct set of orgs the entity's peers belong to — and behave like protocols: a
*new* org contacted since label time is drift.


Worked example — subnet composition drift
------------------------------------------

Suppose an analyst labels ``10.0.1.0/24`` as **"IoT LAN"** while looking at week 1,
where its members are all IoT sensors:

.. code-block:: text

   baseline (captured at label time, from week 1):
     deviceTypes = [IOT]
     protocols   = [TLS]

By week 8, workstations have appeared in the same CIDR and are speaking Windows
networking and mail protocols:

.. code-block:: text

   current (week 8, the latest snapshot):
     deviceTypes = [IOT, SERVER, MOBILE, ROUTER]
     protocols   = [TLS, HTTP, NBSS, SMTP, IMAP]

The set-difference yields the ``stale_fields``:

.. code-block:: text

   device type appeared: SERVER
   device type appeared: MOBILE
   device type appeared: ROUTER
   protocol appeared: HTTP
   protocol appeared: NBSS
   protocol appeared: SMTP
   protocol appeared: IMAP

The subnet's "IoT LAN" label is flagged **Stale**, and these exact lines are shown
to the analyst so they can see *why* before deciding to update or dismiss it.


Where it surfaces in the UI
---------------------------

- **IP / Device roles.** In the entity detail modal, a confirmed-but-stale role
  shows a **Stale** badge with the drifted fields, plus **Update label** and
  **Dismiss — label is still correct** actions. In Monitor mode, stale labels are
  also raised as a **Change Event** ("Manual label staleness") in the change feed.
- **Subnet definitions.** In the Subnet Definitions panel, a stale subnet shows a
  **Stale** badge on its row. Opening it reveals a stale banner listing the
  drifted device types / protocols, a **Dismiss** action, and a **Snapshot
  History** table showing the subnet's member count, dominant device types, and
  protocols in every snapshot it appeared in — so the drift is visible at a glance.


What it is *not*
----------------

- It is **not** anomaly detection or threat scoring. A stale flag means "the label
  no longer matches observed behaviour," not "something is wrong." Benign changes
  (a new service deployed, DHCP reassignment bringing in different hosts) will
  legitimately raise it.
- It does **not** use the AI/LLM. AI is only involved when an analyst *asks* for a
  suggested role or subnet label; the staleness comparison that follows is
  entirely rule-based.
- It does **not** rank protocols by importance. "Dominant" is a frequency cutoff,
  not a curated list of security-relevant protocols.
