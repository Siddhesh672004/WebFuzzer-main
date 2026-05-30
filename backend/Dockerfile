FROM node:20-alpine AS base
WORKDIR /app
COPY package.json package-lock.json ./
COPY shared/package.json ./shared/
COPY backend/package.json ./backend/

FROM base AS deps
RUN npm ci --workspace backend --workspace shared --ignore-scripts

FROM deps AS production
COPY shared/ ./shared/
COPY backend/ ./backend/
COPY worker/src/scoring/ ./worker/src/scoring/
COPY worker/src/knowledge/ ./worker/src/knowledge/
ENV NODE_ENV=production
EXPOSE 4000
CMD ["node", "backend/src/server.js"]
