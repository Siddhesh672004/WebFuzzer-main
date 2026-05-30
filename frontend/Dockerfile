FROM node:20-alpine AS base
WORKDIR /app

COPY package.json package-lock.json ./
COPY shared/package.json ./shared/
COPY frontend/package.json ./frontend/

FROM base AS deps
RUN npm ci --workspace shared --workspace frontend --ignore-scripts

FROM deps AS build
COPY shared/ ./shared/
COPY frontend/ ./frontend/
ENV NODE_ENV=production
RUN npm run build --workspace frontend

FROM nginx:alpine AS production
COPY --from=build /app/frontend/dist /usr/share/nginx/html
COPY frontend/nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
