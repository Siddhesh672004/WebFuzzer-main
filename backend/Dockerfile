FROM node:20-alpine AS base
WORKDIR /app

# Copy all workspace manifests first (layer cache for npm ci)
COPY package.json package-lock.json ./
COPY shared/package.json ./shared/
COPY backend/package.json ./backend/
COPY worker/package.json ./worker/
COPY payloads/package.json ./payloads/

FROM base AS deps
RUN npm ci --workspace shared --workspace backend --workspace worker --workspace payloads --ignore-scripts

FROM deps AS production
# Copy all source needed by backend + the worker scoring/knowledge modules it imports
COPY shared/ ./shared/
COPY backend/ ./backend/
COPY worker/src/scoring/ ./worker/src/scoring/
COPY worker/src/knowledge/ ./worker/src/knowledge/
COPY payloads/ ./payloads/

ENV NODE_ENV=production
EXPOSE 4000
CMD ["node", "backend/src/server.js"]
