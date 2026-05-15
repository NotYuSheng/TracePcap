Sample Files
============

The ``sample-files/`` directory contains example PCAP files and a generator
script to help you test and explore TracePcap's features.

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

Adding Your Own PCAP Files
--------------------------

Place any ``.pcap``, ``.pcapng``, or ``.cap`` file in ``sample-files/`` and
upload it via the TracePcap UI. There is no restriction on the content —
any valid capture file is accepted.
