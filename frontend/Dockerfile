# Production image: build the static bundle with Node, then serve it with nginx —
# no Node runtime, dev server, or source ships in the final image.

FROM node:22-slim AS builder

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm ci

COPY . .

# Vite bakes VITE_* variables into the bundle at build time (they cannot be changed
# at container start). Default to a relative path so nginx.conf's reverse proxy to
# the backend service works regardless of the public hostname this is served from —
# override only if the frontend and API are served from different origins.
ARG VITE_API_BASE_URL=/api/v1
ENV VITE_API_BASE_URL=$VITE_API_BASE_URL
RUN npm run build


FROM nginx:1.27-alpine AS runtime

COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=builder /app/dist /usr/share/nginx/html

EXPOSE 80

# 127.0.0.1, not localhost: this image's /etc/hosts resolves localhost to ::1
# first, but nginx (see nginx.conf) only binds the IPv4 wildcard, so the IPv6
# attempt fails with "connection refused" before wget ever falls back to IPv4.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget -qO- http://127.0.0.1/ >/dev/null || exit 1

CMD ["nginx", "-g", "daemon off;"]
