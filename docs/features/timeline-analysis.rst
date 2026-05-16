Timeline Analysis
=================

The Timeline tab provides a chronological view of network traffic, helping
you understand when activity occurred and how traffic patterns evolved over
the capture period.

How Timeline Data Is Derived
-----------------------------

Understanding the binning logic prevents misinterpretation of bar heights,
especially for long or high-rate captures.

Bin Assignment
~~~~~~~~~~~~~~

Every conversation stored in the database is assigned to exactly **one** time
bin based on its ``startTime`` (the timestamp of its first observed packet).
The bin index is computed in O(1):

.. code-block:: text

   binIndex = floor( (conversation.startTime - captureStart) / intervalSeconds )

A conversation that spans multiple bins (e.g. a long-lived TCP session) is
counted **only in the bin where it started**, not spread across bins for its
entire duration. This means a 10-minute TCP session that started at T=0
appears only in the T=0 bin, even though traffic continued through bins 1–9.

What the Y-axis Measures
~~~~~~~~~~~~~~~~~~~~~~~~

Each bar accumulates values from every conversation that started in that bin:

- **Packet count mode**: sum of ``packetCount`` for all conversations in the
  bin. ``packetCount`` is the total number of tshark output lines (raw frames)
  for the conversation, **both directions combined**.
- **Bytes mode**: sum of ``totalBytes`` for all conversations in the bin.
  ``totalBytes`` is the sum of ``frame.len`` (on-wire frame length including
  all headers) for all packets in the conversation.

Because a conversation is counted only once (at its start time), a burst of
many **short** connections will produce a tall bar at their start time, while
a single **long** connection of the same total bytes will produce one bar at
the start of the session only. The chart shows conversation activity density,
not continuous throughput.

Protocol Color Breakdown
~~~~~~~~~~~~~~~~~~~~~~~~

Each bar is split by protocol. The protocol label used is the
``_ws.col.Protocol`` value from the first tshark pass — the Wireshark display
column label uppercased and truncated to 20 characters. Conversations with the
same protocol value are grouped together within a bar segment.

Auto-Interval Adjustment
~~~~~~~~~~~~~~~~~~~~~~~~

When "Auto" granularity is selected, or when the requested granularity would
produce more data points than the configured maximum, ``TimelineService``
automatically widens the interval:

.. code-block:: text

   adjustedInterval = ceil( captureDurationSeconds / maxDataPoints )

where ``maxDataPoints`` defaults to a server-side configuration value. The
adjustment is logged at INFO level:

.. code-block:: text

   Timeline auto-adjusted: duration=3600s, requestedInterval=1s,
   adjustedInterval=4s, expectedBins=3600, limit=500

This means: if you request 1-second bins for a 1-hour capture but the
maximum data points is 500, the interval is automatically widened to
``ceil(3600/500)`` = 8 seconds per bin. The UI shows the actual interval used.

Chart Layout
------------

Traffic is visualised as a stacked bar chart:

- The **X axis** represents time bins, labelled with the bin start time.
- The **Y axis** represents either packet count or byte volume (toggle between
  the two using the view control).
- Each bar is color-coded by **protocol** (``_ws.col.Protocol`` label).

Time Granularity
----------------

You can control how finely the time axis is divided:

- **Auto** — TracePcap picks a suitable granularity based on the capture
  duration (e.g. seconds for a 1-minute capture, minutes for a 1-hour
  capture), subject to the maximum data-points limit described above.
- **Manual** — choose from: 1 s, 5 s, 30 s, 1 min, 5 min, 15 min, 1 hour.
  The selected interval may be automatically widened if it would exceed the
  data-points limit.

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
