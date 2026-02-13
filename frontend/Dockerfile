FROM node:18-alpine

# Create app directory
WORKDIR /usr/src/app

# Install only production dependencies (package-lock optional)
COPY package*.json ./
RUN npm ci --only=production

# Copy app sources
COPY . .

# Cloud Run expects the service to listen on $PORT (default 8080)
ENV PORT 8080

EXPOSE 8080

CMD ["node", "server/server.js"]
