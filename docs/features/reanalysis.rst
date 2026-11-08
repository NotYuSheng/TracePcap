Re-analysing a Capture
======================

The analysis options (application detection, IDS alerts, file extraction) are
chosen when a capture is uploaded. To see a capture with different options,
re-analyse it from its **File** tab on the Analysis page.

The File Tab
------------

- **How this capture was analysed**: which of nDPI, Suricata and file
  extraction were on.
- **Re-analyse with other options** opens the options; pick them and click
  **Re-analyse**. You're taken to the new version while it's analysed.
- **Versions**: once a capture has been re-analysed, every version is listed,
  the original upload first, each with its options and an **Open** button.

Versions, Not Replacements
--------------------------

Re-analysing makes a **new version** of the capture with its own id, its own
copy of the capture in storage, and its own analysis. The version you started
from is left as it was. That means:

- The original's analysis, and the labels, notes and node roles set on it, are
  kept on the original. They aren't carried over, because they belong to that
  analysis's conversations and hosts.
- The capture's **own detection rules** are copied to the new version and
  applied when it's analysed.
- Deleting either version doesn't affect the other.
- A version of a version is a version of the original: the list stays flat.
- Networks keep the version they were added with. To monitor a new version,
  add it to the network.
- Uploading the same file again still points you at the original upload
  (duplicate check); versions don't count as uploads.

A capture can't be re-analysed while it's being analysed, or once retention has
deleted its packets (``PACKET_RETENTION_HOURS``), since there's nothing left to
analyse.
