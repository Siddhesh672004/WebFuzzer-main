FROM node:20-alpine AS base
WORKDIR /app

COPY package.json package-lock.json ./
COPY shared/package.json ./shared/
COPY worker/package.json ./worker/

FROM base AS deps
RUN npm ci --workspace shared --workspace worker --ignore-scripts

FROM deps AS production
COPY shared/ ./shared/
COPY worker/ ./worker/

# Chromium for Puppeteer screenshot evidence (Feature 2). On Alpine we install
# the system Chromium via apk rather than letting Puppeteer download its own
# bundled build (which is glibc-linked and won't run on musl). Screenshots are
# still opt-in at runtime via SCAN_SCREENSHOTS — these packages just make the
# capability available.
RUN apk add --no-cache \
  chromium \
  nss \
  freetype \
  harfbuzz \
  ca-certificates \
  ttf-freefont

ENV NODE_ENV=production \
    PUPPETEER_SKIP_CHROMIUM_DOWNLOAD=true \
    PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium-browser
CMD ["node", "worker/src/index.js"]
