The Overview
============

A capture's **Overview** is the first section of its analysis. Traffic is on
the left and what needs a look is on the right.

Every section says where its numbers come from, in a small tag beside its
heading, for example **from nDPI** or **from tshark**. Click the tag for how
the numbers are worked out.

The Traffic (left)
------------------

- **Totals**: hosts, conversations, packets and how long the capture runs.
- **Activity over time**: packets per time slice across the capture, from the
  packet timestamps tshark reads. Hover a bar for its count.
- **Traffic mix**: two stacked bars, each with its table.

  - **Protocols** is the highest-layer protocol tshark recognises in each
    packet, as a share of packets.
  - **Categories** is nDPI's category for each conversation's application,
    such as Web, Media or System.

- **Busiest conversations**: the conversations that carried the most bytes,
  with a link to all conversations.

What Needs a Look (right)
-------------------------

- **Needs a look**: how many conversations were flagged, and by which source:

  - **nDPI risks**: built-in heuristics, such as a known-malicious TLS
    fingerprint;
  - **Suricata**: Emerging Threats Open signatures, when Suricata was on for
    this capture;
  - **custom rules**: yours.

  Below the count are the nDPI risk names and the custom rules matched; click
  one to see its conversations. The card also links to the files found in the
  traffic.
- **Confirmed findings**, when the investigation has answers.
- **Applications detected** (from nDPI) and **Dissected protocols** (from
  tshark). Click a badge for its details.

The capture's own detection rules are in the **Capture** tab, with the rules
picker and the report.
