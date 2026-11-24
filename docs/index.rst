TracePcap Documentation
=======================

**TracePcap** is a self-hosted PCAP analysis workbench for black-box network analysis — situations where you work from captured traffic alone, with no prior knowledge of the network. It derives device inventory, topology, session content, and behavioural patterns purely from observed packets, making it well-suited for network audits, incident response, penetration test reconnaissance, and research.

Designed for air-gapped and offline deployments — GeoIP lookups use a bundled offline database by default, with optional enrichment via ipinfo.io when internet access is available.

.. toctree::
   :maxdepth: 2
   :caption: Getting Started

   getting-started/prerequisites
   getting-started/supported-architectures
   getting-started/installation
   getting-started/offline-deployment
   getting-started/kubernetes

.. toctree::
   :maxdepth: 2
   :caption: Architecture

   architecture/c4
   architecture/layers
   architecture/enforcement
   architecture/adjudication-explainability
   architecture/knowledge-layer

.. toctree::
   :maxdepth: 2
   :caption: Features

   features/pcap-upload
   features/analysis-navigation
   features/analysis-overview
   features/reanalysis
   features/address-reuse
   features/network-devices
   features/overlapping-networks
   features/network-address-config
   features/network-visualization
   features/network-time-axis
   features/network-map
   features/packet-replay
   features/device-moves
   features/traffic-groups
   features/comparison
   features/ndpi-analysis
   features/ids-threat-detection
   features/conversations
   features/session-reconstruction
   features/file-extraction
   features/geolocation
   features/mac-lookup
   features/windows-identity
   features/timeline-analysis
   features/capture-chat
   features/background-ai-work
   features/story-mode
   features/custom-signatures
   features/report-export
   features/network-monitor
   features/label-staleness
   features/streaming-upload
   features/settings
   features/roles-and-permissions

.. toctree::
   :maxdepth: 2
   :caption: Configuration

   configuration/environment-variables
   configuration/authentication
   configuration/user-management
   configuration/llm-setup
   configuration/signature-rules

.. toctree::
   :maxdepth: 2
   :caption: Operations

   operations/backup-restore
   operations/logs-monitoring
   operations/production-hardening
   operations/scalability
   operations/storage-redundancy

.. toctree::
   :maxdepth: 2
   :caption: Demo & Sample Data

   sample-files
   demos/strrat-you-dirty-rat
   demos/warmcookie
   demos/lumma-in-the-room-ah
   demos/fake-software-site
   demos/netsupport-rat
   demos/devices-on-a-dhcp-network
   demos/two-sites-one-range

.. toctree::
   :maxdepth: 1
   :caption: Reference

   api-reference
