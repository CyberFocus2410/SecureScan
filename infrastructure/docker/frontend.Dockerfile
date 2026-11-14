# Stage 1: Build
FROM node:20.18.1-alpine AS builder

WORKDIR /app

COPY frontend/package*.json ./
RUN npm ci || npm install

COPY frontend/ ./
RUN npm run build

# Stage 2: Serve with NGINX reverse proxy & SPA router
FROM nginx:1.27-alpine

# Copy built static assets
COPY --from=builder /app/dist /usr/share/nginx/html

# Copy custom Nginx configuration
COPY infrastructure/docker/nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
