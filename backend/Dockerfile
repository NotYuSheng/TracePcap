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
#   libpcap0.8   — shared lib for Pcap4J (runtime only; -dev headers not needed)
#   tshark       — fallback parser for multi-interface pcapng
#   libndpi-bin  — ndpiReader for application-layer identification (from ntop repo
#                  for latest version with H.225 session tracking / H.245 support)
#   tzdata       — timezone data
# ntop's apt repository provides newer nDPI builds than Ubuntu 22.04's 4.2-2.
# BuildKit cache mount keeps downloaded .deb files cached across rebuilds.
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
        libpcap0.8 \
        tshark \
        ndpi \
        tzdata \
        gosu && \
    apt-get purge -y --auto-remove curl gnupg

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
