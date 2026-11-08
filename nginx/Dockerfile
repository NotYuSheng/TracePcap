# Stage 1: Build the React application
# Runs on the build machine's architecture: the static bundle is portable, so there is nothing to
# gain from compiling it under emulation during a cross-architecture build.
FROM --platform=$BUILDPLATFORM node:22-alpine AS builder

# Build-time memory cap for tsc and vite (compose's deploy.resources don't apply to builds).
# Override with BUILD_NODE_MAX_HEAP_MB.
ARG BUILD_NODE_MAX_HEAP_MB=1536
ENV NODE_OPTIONS="--max-old-space-size=${BUILD_NODE_MAX_HEAP_MB}"

WORKDIR /app

# Copy package files and .npmrc (needed for legacy-peer-deps flag)
COPY frontend/package*.json frontend/.npmrc* ./

# Install dependencies
RUN npm ci

# Copy frontend source code
COPY frontend ./

# Build-time env vars (passed from docker-compose build args / root .env)
ARG VITE_API_BASE_URL=/api/v1
ARG VITE_SUPPORTED_FILE_TYPES=.pcap,.pcapng,.cap
ARG VITE_NETWORK_DIAGRAM_CONVERSATION_LIMIT=false
# No default here: when unset, the APP_VERSION file is used (see the build step below).
ARG VITE_APP_VERSION
# OIDC/Keycloak auth (off by default; enabled via docker-compose.prod.yml)
ARG VITE_AUTH_ENABLED=false
ARG VITE_OIDC_AUTHORITY=
ARG VITE_OIDC_CLIENT_ID=tracepcap-frontend
ARG VITE_OIDC_REALM=tracepcap
ENV VITE_API_BASE_URL=${VITE_API_BASE_URL}
ENV VITE_SUPPORTED_FILE_TYPES=${VITE_SUPPORTED_FILE_TYPES}
ENV VITE_NETWORK_DIAGRAM_CONVERSATION_LIMIT=${VITE_NETWORK_DIAGRAM_CONVERSATION_LIMIT}
ENV VITE_APP_VERSION=${VITE_APP_VERSION}
ENV VITE_AUTH_ENABLED=${VITE_AUTH_ENABLED}
ENV VITE_OIDC_AUTHORITY=${VITE_OIDC_AUTHORITY}
ENV VITE_OIDC_CLIENT_ID=${VITE_OIDC_CLIENT_ID}
ENV VITE_OIDC_REALM=${VITE_OIDC_REALM}

# Build the application. With no VITE_APP_VERSION build arg, the version comes from the
# APP_VERSION file (kept current by .github/workflows/app-version.yml). It lives in its own
# file, not docker-compose.yml, so the bot's bump PR doesn't trigger the compose workflows.
COPY APP_VERSION /tmp/APP_VERSION
RUN VITE_APP_VERSION="${VITE_APP_VERSION:-$(tr -d '[:space:]' < /tmp/APP_VERSION)}" npm run build

# Stage 2: Serve with nginx and proxy to backend
FROM nginx:alpine

# Install gettext for envsubst (used in entrypoint script) and tzdata for timezone
RUN apk add --no-cache gettext tzdata

# Set timezone to Singapore
ENV TZ=Asia/Singapore
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

# Copy built assets from builder stage
COPY --from=builder /app/dist /usr/share/nginx/html

# Create templates directory
RUN mkdir -p /etc/nginx/templates

# Copy nginx configuration template
COPY nginx/nginx.conf.template /etc/nginx/templates/nginx.conf.template

# Copy and set up entrypoint script
COPY nginx/docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

# Expose port 80
EXPOSE 80

# Use custom entrypoint to process template, then start nginx
ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["nginx", "-g", "daemon off;"]
