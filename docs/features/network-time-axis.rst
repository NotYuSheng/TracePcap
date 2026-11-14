Network Traffic Over Time
=========================

The network graph shows every conversation in a capture at once. The **time
axis** above it shows the traffic over the capture, and picks a window of it:
the graph then shows only what happened in that window, so you can watch hosts
come and go, see when a conversation started, and follow a device through the
capture.

The Time Axis
-------------

Above the graph on **Network Visualization**:

- **The chart** is the capture's traffic: bytes per interval from its first to
  its last conversation. A conversation's bytes are spread over its duration, so
  a long download fills every interval it spans rather than one spike where it
  started.
- **The window** is the shaded part of the chart. Set it by:

  - clicking the chart, which centres the window there;
  - dragging **From** and **To** (they also work from the keyboard);
  - choosing a **Window** width (5% to 50% of the capture, with its length).

- **Play** slides the window from the start of the capture to the end, at the
  chosen **Speed** (1× crosses the whole capture in about 30 seconds). **Pause**
  stops it where it is.
- **Show all** goes back to the whole capture.

The readout gives the window's times and how many of the conversations were
active in it.

Traffic Dots
------------

With **Animate traffic** on (the default, unless your system asks for reduced
motion), dots move along every edge shown, in the edge's colour:

- **More dots** on busier conversations: one for a trickle, up to four for the
  heaviest.
- **Both ways** when the conversation went both ways: every other dot runs back.
- They follow the edge's own shape, curved or straight, and only edges in the
  time window (and not hidden by hovering a node) have them.

Played together, the window and the dots show traffic starting, moving and
stopping over the capture. On a very large graph only the 400 busiest edges
animate, so it stays smooth. Animation stops while the browser tab is hidden.

What the Window Does
--------------------

- **Edges** are shown only for conversations active in the window: started
  before it ends and not ended before it starts.
- **Nodes** with no conversation in the window are greyed out but stay where they
  are, so the layout doesn't jump as the window moves. Their labels stay, so a
  quiet host is still findable.
- **Node-to-Node Volume** below the graph counts only the window's
  conversations.
- The window works on top of the graph's other filters (protocol, application,
  risks and so on): the chart shows the filtered traffic, and the window picks
  from it.

A conversation's time is when it started and ended. A long-lived one, such as a
router's periodic ARP, stays active in every window it spans.

Example
-------

An address that changed hands (see :doc:`address-reuse`) shows its devices in
turn: early in ``dhcp_address_reuse.pcap`` only Alice's laptop on ``10.0.0.50``
is active; late in it, the visitor's phone and its beaconing are, and the laptop
is greyed out. :doc:`../demos/devices-on-a-dhcp-network` walks through it.
