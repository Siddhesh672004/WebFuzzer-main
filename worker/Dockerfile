FROM node:20-alpine AS base
WORKDIR /app
COPY package.json package-lock.json ./
COPY shared/package.json ./shared/
COPY worker/package.json ./worker/

FROM base AS deps
RUN npm ci --workspace worker --workspace shared --ignore-scripts

FROM deps AS production
COPY shared/ ./shared/
COPY worker/ ./worker/
ENV NODE_ENV=production
CMD ["node", "worker/src/index.js"]
