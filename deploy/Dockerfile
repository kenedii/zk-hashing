# Build from the repository root: docker build -f deploy/Dockerfile .
FROM node:22-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY server/ ./server/
COPY web/ ./web/
RUN npm run build && npm prune --omit=dev

FROM node:22-alpine
WORKDIR /app
COPY --from=build --chown=node:node /app/package*.json ./
COPY --from=build --chown=node:node /app/node_modules ./node_modules
COPY --from=build --chown=node:node /app/server ./server
COPY --from=build --chown=node:node /app/web ./web
USER node
ENV PORT=8080
EXPOSE 8080
CMD ["node", "server/app.js"]
