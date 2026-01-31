# OpenClaw/ClawdBot Railway Template
FROM node:20-slim

# Install pnpm and required system dependencies
RUN corepack enable && corepack prepare pnpm@latest --activate
RUN apt-get update && apt-get install -y \
    git \
    curl \
    chromium \
    chromium-sandbox \
    && rm -rf /var/lib/apt/lists/*

# Set Puppeteer to use installed Chromium
ENV PUPPETEER_SKIP_CHROMIUM_DOWNLOAD=true
ENV PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium

WORKDIR /app

# Clone OpenClaw repository
RUN git clone https://github.com/openclaw/openclaw.git .

# Install dependencies
RUN pnpm install

# Build the application
RUN pnpm run build

# Expose the default port
EXPOSE 3000

# Health check endpoint
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:3000/health || exit 1

# Start the application
CMD ["pnpm", "run", "start"]
