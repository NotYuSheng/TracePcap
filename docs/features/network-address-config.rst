Per-Network Address Configuration
=================================

Three lists describe your address space:

- **Subnet labels**: names for address ranges, shown in the monitor's subnet
  views and used to notice when a subnet's make-up changes.
- **Internal / external ranges**: ranges forced to count as internal or
  external, overriding the usual private-address rules. They decide what is
  "internal" in change detection, the subnet view, Story and the Network
  Cluster.
- **Organisations**: which organisation owns a range, used to group hosts in
  the Network Cluster view.

Each list has a **shared default** that applies everywhere, and every monitored
network can adjust it for itself.

Adjusting a Network
-------------------

On a network's page, click **Addresses**. Each list shows the default's entries
and the network's own, badged by where they come from:

.. list-table::
   :header-rows: 1
   :widths: 25 75

   * - Badge
     - Meaning
   * - ``default``
     - The shared default's entry, used here as is. **Override** sets a
       different value in this network; **Hide here** removes it in this
       network only.
   * - ``overridden here``
     - This network's value for a range the default also has. **Revert to
       default** brings the default's value back.
   * - ``hidden here``
     - The default's entry, switched off in this network. **Show again** undoes
       it.
   * - ``this network``
     - A range only this network has. **Remove** deletes it.

**Add for this network** adds an entry only this network has. Changes apply to
the network's existing snapshots straight away; nothing is re-analysed.

Entries match **per range** (CIDR): a network entry for ``10.0.0.0/8``
replaces the default's ``10.0.0.0/8`` entry, and leaves the default's other
entries, including narrower ones such as ``10.1.0.0/16``, as they are.

Where Each Applies
------------------

- **Monitor views** (a network's snapshots, change detection, subnets): that
  network's lists.
- **Analysis page**: the default, or a network's lists when it's picked in the
  **Viewing with** picker at the top of the page. The Network Cluster view
  follows the picker; Story still uses the default.
- **Captures in no network**: the default.

A snapshot's own subnet overrides (set when adding or editing a snapshot) still
come first, then the network's entries, then the default.

Subnet Staleness Is Per Network
-------------------------------

When you confirm a subnet's label, TracePcap records the subnet's make-up
(device types and protocols) from the network's latest snapshot, and flags the
label as stale when later snapshots differ. That record is kept **per
network**, so confirming or dismissing in one network doesn't reset another.

Who Can Change What
-------------------

A network's entries need the **Edit network settings** permission (default:
analysts). Every change is recorded in the audit log. See
:ref:`settings-permissions`.
