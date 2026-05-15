Timeline Analysis
=================

The Timeline tab provides a chronological view of network traffic, helping
you understand when activity occurred and how traffic patterns evolved over
the capture period.

Chart Layout
------------

Traffic is visualised as a stacked bar chart:

- The **X axis** represents time (divided into configurable buckets).
- The **Y axis** represents packet count or byte volume (toggle between the
  two using the view control).
- Each bar is color-coded by **protocol** so you can see the protocol mix
  at a glance.

Time Granularity
----------------

You can control how finely the time axis is divided:

- **Auto** — TracePcap picks a suitable granularity based on the capture
  duration (e.g. seconds for a 1-minute capture, minutes for a 1-hour
  capture).
- **Manual** — choose from: 1 s, 5 s, 30 s, 1 min, 5 min, 15 min, 1 hour.

Protocol Breakdown
------------------

A legend below the chart lists every protocol color. Clicking a legend entry
toggles that protocol's visibility, letting you isolate specific traffic types.

Interaction
-----------

- **Hover** over a bar to see an exact breakdown of protocols and volumes for
  that time bucket.
- **Click** a bar to filter the Conversations tab to only the conversations
  active during that time bucket.
