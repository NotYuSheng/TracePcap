# Stage 1: Build the React application
FROM node:20-alpine AS builder

WORKDIR /app

# Copy package files
COPY frontend/package*.json ./

# Install dependencies
RUN npm ci

# Copy frontend source code
COPY frontend ./

# Build the application
RUN npm run build

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
