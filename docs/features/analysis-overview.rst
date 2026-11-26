The Overview
============

A capture's **Overview** is the first section of its analysis. Traffic is on
the left and what needs a look is on the right.

Every section says where its numbers come from, in a small tag beside its
heading, for example **from nDPI** or **from tshark**. Click the tag for how
the numbers are worked out.

The Traffic (left)
------------------

- **Totals**: hosts, conversations, packets and how long the capture runs
  (minutes and seconds for a short capture; days, months or years for a long
  one).
- **Activity over time**: packets per time slice across the capture, from the
  packet timestamps tshark reads. Hover a bar for its count.
- **Where the traffic goes**: the hosts grouped by organisation or country, as
  tiles sized by traffic, or on a world map. Click a group for its hosts and who
  it talks to (see :doc:`traffic-groups`).
- **Flows between organisations**: the largest flows between two
  organisations, each band as thick as its traffic.
- **Traffic mix**: two stacked bars, each with its table; the tables show their
  top ten rows, with **Show all** for the rest.

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
- **Investigation Summary**, when the investigation has answers or ruled out candidates: each answer
  with **How we got here**, and **Considered and ruled out** (see :doc:`story-mode`).
- **Worth a look**: the protocols in this capture, grouped by the investigation category they help
  answer (see :doc:`../architecture/investigation-framework`), each with what it shows there and a
  link to its conversations. Categories that point at the same traffic and have the same status
  share one group (a C2 server and Command and Control, both open, both point at DNS, TLS and HTTP). Kerberos and LDAP for *who
  is signed in*, DHCP and NetBIOS for *which machine it is*, DNS, TLS and HTTP for *command and
  control*, SMB, DCE-RPC and RDP for *lateral movement*, Kerberos and NTLM for *account attacks*,
  mail and FTP for *data leaving*, remote-control tools for *remote access*. A question the
  Investigation Summary answered is marked **Answered**; one whose candidates were tested and ruled out
  is **Ruled out**; one nothing concluded is **Open**, so its protocols are where to look. Nothing
  shows until the investigation has loaded. Categories with none of their protocols in the capture
  are left out; every application counts, not only the top ones the Overview lists.
- **Applications detected** (from nDPI) and **Dissected protocols** (from
  tshark). Click a badge for its details.

The capture's own detection rules are in the **Capture** tab, with the rules
picker and the report.

When two networks in the capture use the same address range (two sites or two
VLANs on one subnet), a card at the bottom of the overview says so and lists
each network with its DHCP clients.
