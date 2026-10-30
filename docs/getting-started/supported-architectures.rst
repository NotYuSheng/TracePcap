Supported CPU Architectures
===========================

TracePcap supports **amd64** (x86-64) and **arm64** (aarch64). The limit comes
from the CPU architecture, not the operating system: any host that runs Docker
on one of these two architectures can run the stack, including Apple Silicon
Macs, whose Docker containers run as ``linux/arm64``.

To see which one you have:

.. code-block:: bash

   docker version --format '{{.Server.Arch}}'

Support Matrix
--------------

.. list-table::
   :header-rows: 1
   :widths: 14 34 38 14

   * - Architecture
     - Typical hardware
     - What is missing
     - Status
   * - ``amd64``
     - Most servers and PCs, Intel Macs
     - Nothing
     - Supported
   * - ``arm64``
     - Apple Silicon, AWS Graviton, Ampere, Raspberry Pi 4/5 on a 64-bit OS
     - Nothing. nDPI is compiled from source during the build
     - Supported
   * - ``ppc64le``
     - IBM Power
     - nDPI package, MinIO image
     - Not supported
   * - ``s390x``
     - IBM Z
     - nDPI package, MinIO image, Keycloak image
     - Not supported
   * - ``riscv64``
     - RISC-V boards
     - nDPI package, Java runtime image, MinIO image, Keycloak image
     - Not supported
   * - ``arm/v7``
     - Older Raspberry Pi, 32-bit Raspberry Pi OS
     - nDPI package, Java runtime image, MinIO image, Keycloak image
     - Not supported
   * - ``386``
     - Legacy 32-bit PCs
     - nDPI package, Java runtime image, MinIO image, Keycloak image,
       ``tshark``, ``suricata`` and ``gosu`` packages
     - Not supported

Keycloak is only needed by the authentication overlays
(``docker-compose.prod.yml`` and ``docker-compose.offline-prod.yml``).

Where a base image exists but the architecture is unsupported, the build stops
at the ``ndpi`` stage of ``backend/Dockerfile`` with an
``Unsupported architecture`` message.

The Maven and Node build stages run on the build machine's own architecture,
because the JAR and the frontend bundle are portable.

How nDPI Differs on arm64
-------------------------

ntop's apt repository publishes the ``ndpi`` package for x64 only, so the two
architectures get nDPI differently:

.. list-table::
   :header-rows: 1
   :widths: 20 40 40

   * -
     - amd64
     - arm64
   * - Source
     - ``ndpi`` package from ``packages.ntop.org``
     - ``6.0-stable`` branch of ``github.com/ntop/nDPI``, compiled in the
       ``ndpi`` stage of ``backend/Dockerfile``
   * - Updates
     - Latest package at build time
     - Latest commit on the branch at build time
   * - Version record
     - ``/opt/ndpi-version`` holds the package version
     - ``/opt/ndpi-version`` holds the branch and short commit

Both are the same stable line, and security fixes reach both when the image is
rebuilt. To refresh nDPI, rebuild the image without cache, as on amd64:

.. code-block:: bash

   docker compose build --no-cache backend

When ntop's package moves to a new major version, move ``NDPI_BRANCH`` in
``backend/Dockerfile`` to the matching ``<version>-stable`` branch so the two
architectures stay on the same line.

The other options were rejected because they change results or the runtime:

- Ubuntu 22.04's own ``libndpi-bin`` is version 4.2, which lacks H.225/H.245
  session tracking and several protocol signatures. Detection would silently
  differ between architectures.
- ntop's ARM packages are built for Raspberry Pi OS on Debian, not for the
  Ubuntu 22.04 runtime image.

Images and Offline Deployment
-----------------------------

Images on GHCR are published for both ``linux/amd64`` and ``linux/arm64``, so
``docker pull`` selects the right one automatically.

``scripts/pull-and-save-images.sh`` saves images for the architecture of the
machine it runs on, and an image saved on one architecture does not run on the
other. For an air-gapped arm64 host, run the script on an internet-connected
arm64 machine. See :doc:`offline-deployment`.

Building for the Other Architecture
-----------------------------------

To build an image for the architecture you are not on, use ``docker buildx``
with emulation available. For example, on an amd64 machine:

.. code-block:: bash

   docker buildx build --platform linux/arm64 backend

Emulated builds are much slower, particularly the nDPI compile. Running the
stack under emulation is not recommended, because ``tshark``, nDPI and Suricata
are all CPU-bound.
