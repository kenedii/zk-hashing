FROM node:18-alpine

# Create app directory
WORKDIR /usr/src/app

# Copy frontend package.json (context assumed to be repo root when building)
COPY frontend/package*.json ./

# Install only production dependencies
RUN npm ci --only=production

# Copy only the frontend app and the zk-hash library from the repo root
COPY frontend/server ./server
COPY frontend/public ./public
COPY zk-hash /usr/src/zk-hash

# Cloud Run expects the service to listen on $PORT
ENV PORT 8080

EXPOSE 8080

CMD ["node", "server/server.js"]
