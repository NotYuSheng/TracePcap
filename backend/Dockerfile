# Multi-stage build for Spring Boot application
# Stage 1: Build the application
FROM maven:3.9-eclipse-temurin-21-alpine AS build

WORKDIR /app

# Copy pom.xml and download dependencies (cached layer)
COPY pom.xml .
RUN mvn dependency:go-offline -B

# Copy source code and build
COPY src ./src
RUN mvn clean package -DskipTests -B

# Stage 2: Runtime
FROM eclipse-temurin:21-jre-jammy

WORKDIR /app

# Install runtime dependencies:
#   tshark    — PCAP/pcapng parser
#   ndpi      — ndpiReader for application-layer DPI (latest from ntop apt repo)
#   suricata  — offline IDS engine for signature-based threat detection (eve.json)
#   tzdata    — timezone data
#   gosu      — privilege-drop helper for entrypoint
#
# The ntop apt repo is required because Ubuntu 22.04's built-in nDPI (4.2-2)
# lacks H.225/H.245 session tracking and several protocol signatures added in v5.
#
# nDPI is intentionally unpinned: ntop's stable repo only keeps the latest
# rolling build, so pinning an exact version breaks the build once that .deb is
# rotated out (404). We always install the latest available and record it in
# /opt/ndpi-version. To refresh nDPI: rebuild the image and redeploy
# (offline: run pull-and-save-images.sh, transfer tracepcap-backend.tar, load-images.sh).
#
# BuildKit cache mounts keep downloaded apt packages cached across rebuilds.
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    DEBIAN_FRONTEND=noninteractive apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        gnupg && \
    curl -fsSL https://packages.ntop.org/apt-stable/ntop.key \
        | gpg --dearmor -o /usr/share/keyrings/ntop-keyring.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/ntop-keyring.gpg] https://packages.ntop.org/apt-stable/22.04/ x64/" \
        > /etc/apt/sources.list.d/ntop.list && \
    apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        tshark \
        tzdata \
        gosu \
        suricata \
        ndpi && \
    dpkg-query -W -f='${Version}' ndpi > /opt/ndpi-version && \
    dpkg-query -W -f='${Version}' suricata > /opt/suricata-version && \
    apt-get purge -y --auto-remove gnupg curl

# Fetch the Emerging Threats Open ruleset at build time (internet is available during build,
# same curl pattern as the DB-IP MMDB download below). The jammy `suricata` package does not bundle
# `suricata-update`, so we download the ET Open tarball directly and concatenate every *.rules file
# into /etc/suricata/rules/suricata.rules — the path the packaged /etc/suricata/suricata.yaml
# already references (default-rule-path: /etc/suricata/rules + `rule-files: [suricata.rules]`). ET's
# classification / reference configs are copied into /etc/suricata so rule classtypes resolve. This keeps
# signature-based detection fully offline at runtime (per the offline requirement).
#
# Rules are made world-readable so the non-root `spring` runtime user can load them.
#
# To refresh the ruleset in air-gapped deployments: rebuild the image and redeploy
# (offline: run pull-and-save-images.sh, transfer tracepcap-backend.tar, load-images.sh) —
# analogous to the nDPI refresh flow above.
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    DEBIAN_FRONTEND=noninteractive apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends curl && \
    mkdir -p /etc/suricata/rules /tmp/etrules && \
    curl -fsSL "https://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz" \
        | tar -xz -C /tmp/etrules && \
    cat /tmp/etrules/rules/*.rules > /etc/suricata/rules/suricata.rules && \
    cp /tmp/etrules/rules/*.config /etc/suricata/ 2>/dev/null || true && \
    rm -rf /tmp/etrules && \
    date -u +%Y-%m-%d > /opt/suricata-ruleset-version && \
    chmod -R a+rX /etc/suricata && \
    apt-get purge -y --auto-remove curl

# Download DB-IP Lite City MMDB (offline GeoIP).
# Published monthly at https://db-ip.com/db/download/ip-to-city-lite
# Try current month; fall back to previous month if not yet published.
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    DEBIAN_FRONTEND=noninteractive apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends curl && \
    mkdir -p /app/geoip && \
    CUR_YM=$(date +%Y-%m) && \
    PREV_YM=$(date -d "$(date +%Y-%m-01) -1 month" +%Y-%m) && \
    curl -fsSL "https://download.db-ip.com/free/dbip-city-lite-${CUR_YM}.mmdb.gz" \
        | gunzip -c > /app/geoip/dbip-city-lite.mmdb \
    || curl -fsSL "https://download.db-ip.com/free/dbip-city-lite-${PREV_YM}.mmdb.gz" \
        | gunzip -c > /app/geoip/dbip-city-lite.mmdb && \
    apt-get purge -y --auto-remove curl

# Set timezone to Singapore
ENV TZ=Asia/Singapore
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

# Create a non-root user
RUN groupadd -r spring && useradd -r -g spring spring

# Create config directories owned by spring
RUN mkdir -p /app/config /app/config-defaults && chown spring:spring /app/config /app/config-defaults

# Copy entrypoint script and make executable while still root
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

# Copy the built JAR from build stage
COPY --from=build /app/target/*.jar app.jar

# Copy the default signatures file into both locations:
# - /app/config/signatures.yml  — picked up by Docker on first-time named volume init
# - /app/config-defaults/       — fallback used by entrypoint if volume file is missing
COPY --chown=spring:spring config/signatures.yml /app/config/signatures.yml
COPY --chown=spring:spring config/signatures.yml /app/config-defaults/signatures.yml

# Expose the application port
EXPOSE 8080

ENTRYPOINT ["/docker-entrypoint.sh"]
