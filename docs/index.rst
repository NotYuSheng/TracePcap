TracePcap Documentation
=======================

**TracePcap** is a self-hosted PCAP analysis workbench for black-box network analysis — situations where you work from captured traffic alone, with no prior knowledge of the network. It derives device inventory, topology, session content, and behavioural patterns purely from observed packets, making it well-suited for network audits, incident response, penetration test reconnaissance, and research.

Designed for air-gapped and offline deployments — GeoIP lookups use a bundled offline database by default, with optional enrichment via ipinfo.io when internet access is available.

.. toctree::
   :maxdepth: 2
   :caption: Getting Started

   getting-started/prerequisites
   getting-started/installation
   getting-started/offline-deployment

.. toctree::
   :maxdepth: 2
   :caption: Features

   features/pcap-upload
   features/network-visualization
   features/network-intelligence
   features/comparison
   features/ndpi-analysis
   features/ids-threat-detection
   features/conversations
   features/session-reconstruction
   features/file-extraction
   features/geolocation
   features/mac-lookup
   features/timeline-analysis
   features/ai-filter-generator
   features/story-mode
   features/custom-signatures
   features/report-export
   features/network-monitor
   features/streaming-upload

.. toctree::
   :maxdepth: 2
   :caption: Configuration

   configuration/environment-variables
   configuration/authentication
   configuration/llm-setup
   configuration/signature-rules

.. toctree::
   :maxdepth: 2
   :caption: Operations

   operations/backup-restore
   operations/logs-monitoring
   operations/production-hardening

.. toctree::
   :maxdepth: 1
   :caption: Reference

   api-reference
   sample-files
